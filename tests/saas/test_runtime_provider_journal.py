from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.utils import shared_read_scope
from saas.control_plane.onboarding_workflow import (
    RuntimePartitionProvisioner,
    TenantOnboardingWorkflow,
)
from saas.control_plane.outbox import _quarantine_event_hash
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.control_plane.runtime_provider import (
    RuntimeProviderError,
    RuntimeProviderFailureDisposition,
    RuntimeProviderOperation,
    RuntimeProviderOperationKind,
    RuntimeProviderOutcome,
    RuntimeProviderReceipt,
    RuntimeProviderResponse,
    canonical_json,
    canonical_sha256,
)
from saas.control_plane.runtime_provider_journal import (
    PostgresqlRuntimeProviderOperationJournal,
)

_JOURNAL_ROLE = "saas_runtime_provider_journal"
_TABLE = "saas_runtime_provider_operation_journal"
_LEGACY_SEED_TIME = datetime(2026, 8, 25, 4, 0, tzinfo=timezone.utc)


class _ProviderMustNotRun:
    def __init__(self) -> None:
        self.calls = 0

    def __getattr__(self, name: str) -> object:
        del name
        self.calls += 1
        raise AssertionError("a stale legacy wake reached the Runtime Provider")


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


def _seed_legacy_runtime_target_migration_rows(
    connection: sa.Connection,
) -> dict[str, UUID]:
    now = _LEGACY_SEED_TIME
    placement_id = uuid4()
    connection.execute(
        sa.text(
            "INSERT INTO saas_runtime_placements ("
            "id, runtime_type, data_region, failure_domain, database_cluster_ref, "
            "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, status) "
            "VALUES (:id, 'omnigent', 'cn-east-1', 'az-a', 'db-ref', 'object-ref', "
            "'kms-ref', 'schema-r1', 'starter', 'active')"
        ),
        {"id": placement_id},
    )
    plan_snapshot = {"schema_version": 1, "key": "starter"}
    runtime_snapshot = {
        "schema_version": 1,
        "placement_id": str(placement_id),
        "runtime_type": "omnigent",
        "data_region": "cn-east-1",
        "failure_domain": "az-a",
        "official_schema_revision": "schema-r1",
        "capacity_class": "starter",
    }
    plan_json = canonical_json(plan_snapshot)
    runtime_json = canonical_json(runtime_snapshot)
    rows: dict[str, UUID] = {}
    for status in (
        "billing_ready",
        "runtime_ready",
        "project_ready",
        "compensating",
        "active",
    ):
        identifiers = {
            name: uuid4()
            for name in (
                "registration_id",
                "onboarding_id",
                "user_id",
                "tenant_id",
                "space_id",
                "subscription_id",
                "pricing_snapshot_id",
                "entitlement_id",
                "runtime_partition_id",
                "default_project_id",
                "runtime_binding_id",
                "outbox_id",
            )
        }
        rows[status] = identifiers["onboarding_id"]
        connection.execute(
            sa.text(
                "INSERT INTO saas_global_users (id, status, security_version) "
                "VALUES (:user_id, 'active', 1)"
            ),
            identifiers,
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenants "
                "(id, slug, name, status, plan, home_region, lifecycle_version) "
                "VALUES (:tenant_id, :slug, :name, :tenant_status, "
                "'starter', 'cn-east-1', :lifecycle_version)"
            ),
            {
                **identifiers,
                "slug": f"legacy-target-{status.replace('_', '-')}",
                "name": f"Legacy Target {status}",
                "tenant_status": "trial" if status == "active" else "provisioning",
                "lifecycle_version": 2 if status == "active" else 1,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) "
                "VALUES (:space_id, :tenant_id, 'default', 'Default', :space_status)"
            ),
            {
                **identifiers,
                "space_status": "active" if status == "active" else "suspended",
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_self_service_registrations ("
                "id, email_normalized, email_hash, tenant_name, tenant_slug, "
                "default_space_name, default_space_slug, plan_key, plan_policy_revision, "
                "home_region, status, challenge_generation, expires_at, verified_at, "
                "terminal_at, user_id, tenant_id, space_id, subscription_id, "
                "pricing_snapshot_id, entitlement_id, runtime_partition_id, "
                "default_project_id, runtime_binding_id, plan_snapshot, "
                "plan_snapshot_hash, onboarding_id, idempotency_key, request_hash, "
                "version, created_at, updated_at) VALUES ("
                ":registration_id, :email, :email_hash, :tenant_name, :tenant_slug, "
                "'Default', 'default', 'starter', 'starter-v1', 'cn-east-1', "
                "'verified', 1, :expires_at, :now, :now, :user_id, :tenant_id, "
                ":space_id, :subscription_id, :pricing_snapshot_id, :entitlement_id, "
                ":runtime_partition_id, :default_project_id, :runtime_binding_id, "
                "CAST(:plan_snapshot AS json), :plan_snapshot_hash, :onboarding_id, "
                ":registration_key, :registration_hash, 2, :now, :now)"
            ),
            {
                **identifiers,
                "email": f"legacy-target-{status}@example.test",
                "email_hash": sha256(f"email:{status}".encode()).hexdigest(),
                "tenant_name": f"Legacy Target {status}",
                "tenant_slug": f"legacy-target-{status.replace('_', '-')}",
                "expires_at": now + timedelta(days=1),
                "now": now,
                "plan_snapshot": plan_json,
                "plan_snapshot_hash": sha256(plan_json.encode()).hexdigest(),
                "registration_key": sha256(f"registration:{status}".encode()).hexdigest(),
                "registration_hash": sha256(f"registration-hash:{status}".encode()).hexdigest(),
            },
        )
        is_active = status == "active"
        connection.execute(
            sa.text(
                "INSERT INTO saas_tenant_onboardings ("
                "id, registration_id, user_id, tenant_id, space_id, subscription_id, "
                "pricing_snapshot_id, entitlement_id, runtime_partition_id, "
                "runtime_placement_id, runtime_target_snapshot, runtime_request_hash, "
                "default_project_id, runtime_binding_id, plan_key, plan_policy_revision, "
                "plan_snapshot, plan_snapshot_hash, home_region, trial_days, "
                "trial_started_at, trial_ends_at, status, idempotency_key, request_hash, "
                "version, attempt_count, available_at, claimed_at, claim_token, "
                "lease_expires_at, billing_ready_at, runtime_ready_at, project_ready_at, "
                "activated_at, failure_stage, compensation_cursor, last_transition_at) "
                "VALUES (:onboarding_id, :registration_id, :user_id, :tenant_id, "
                ":space_id, :subscription_id, :pricing_snapshot_id, :entitlement_id, "
                ":runtime_partition_id, :placement_id, CAST(:runtime_snapshot AS json), "
                ":runtime_request_hash, :default_project_id, :runtime_binding_id, "
                "'starter', 'starter-v1', CAST(:plan_snapshot AS json), "
                ":plan_snapshot_hash, 'cn-east-1', 14, :trial_started_at, "
                ":trial_ends_at, :status, :saga_key, :saga_hash, 7, 2, :now, "
                ":claimed_at, :claim_token, :lease_expires_at, :billing_ready_at, "
                ":runtime_ready_at, :project_ready_at, :activated_at, "
                ":failure_stage, :compensation_cursor, :now)"
            ),
            {
                **identifiers,
                "placement_id": placement_id,
                "runtime_snapshot": runtime_json,
                "runtime_request_hash": sha256(runtime_json.encode()).hexdigest(),
                "plan_snapshot": plan_json,
                "plan_snapshot_hash": sha256(plan_json.encode()).hexdigest(),
                "trial_started_at": now if is_active else None,
                "trial_ends_at": now + timedelta(days=14) if is_active else None,
                "status": status,
                "saga_key": sha256(f"saga:{status}".encode()).hexdigest(),
                "saga_hash": sha256(f"saga-request:{status}".encode()).hexdigest(),
                "now": now,
                "claimed_at": None if is_active else now,
                "claim_token": None if is_active else uuid4(),
                "lease_expires_at": None if is_active else now + timedelta(minutes=5),
                "billing_ready_at": now,
                "runtime_ready_at": now
                if status in {"runtime_ready", "project_ready", "compensating", "active"}
                else None,
                "project_ready_at": now if status in {"project_ready", "active"} else None,
                "activated_at": now if is_active else None,
                "failure_stage": "runtime_ready" if status == "compensating" else None,
                "compensation_cursor": "project" if status == "compensating" else None,
            },
        )
        connection.execute(
            sa.text(
                "INSERT INTO saas_control_plane_outbox ("
                "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                "idempotency_key, request_hash, attempt_count, available_at) VALUES ("
                ":outbox_id, :tenant_id, 'tenant_onboarding', :aggregate_key, "
                "'onboarding.runtime.requested', CAST(:payload AS json), "
                ":outbox_key, :outbox_hash, 0, :now)"
            ),
            {
                **identifiers,
                "aggregate_key": str(identifiers["onboarding_id"]),
                "payload": canonical_json(
                    {
                        "onboarding_id": str(identifiers["onboarding_id"]),
                        "registration_id": str(identifiers["registration_id"]),
                        "user_id": str(identifiers["user_id"]),
                        "tenant_id": str(identifiers["tenant_id"]),
                        "expected_status": status,
                        "version": 7,
                    }
                ),
                "outbox_key": f"legacy-target-wake-{status}",
                "outbox_hash": sha256(f"outbox:{status}".encode()).hexdigest(),
                "now": now,
            },
        )
    published_id = uuid4()
    billing_onboarding = rows["billing_ready"]
    billing_tenant = connection.scalar(
        sa.text("SELECT tenant_id FROM saas_tenant_onboardings WHERE id = :id"),
        {"id": billing_onboarding},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_control_plane_outbox ("
            "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
            "idempotency_key, request_hash, attempt_count, available_at, published_at) "
            "VALUES (:id, :tenant_id, 'tenant_onboarding', :aggregate_key, "
            "'onboarding.runtime.requested', '{}'::json, 'legacy-published-evidence', "
            ":request_hash, 1, :now, :now)"
        ),
        {
            "id": published_id,
            "tenant_id": billing_tenant,
            "aggregate_key": str(billing_onboarding),
            "request_hash": sha256(b"published-evidence").hexdigest(),
            "now": now,
        },
    )
    rows["published_outbox"] = published_id

    # Prove the migration appends to an existing hash chain instead of merely
    # creating a parallel evidence row.
    prior_facts = {"runtime_target_schema_version": 1, "source": "p0s3_fixture"}
    prior_facts_hash = canonical_sha256(prior_facts)
    prior_event_id = uuid4()
    prior_event_hash = canonical_sha256(
        {
            "aggregate_type": "tenant_onboarding",
            "aggregate_id": str(billing_onboarding),
            "sequence": 1,
            "event_type": "tenant_onboarding.legacy_runtime_target_observed",
            "from_status": "billing_ready",
            "to_status": "billing_ready",
            "facts_hash": prior_facts_hash,
            "previous_hash": "0" * 64,
            "occurred_at": now.isoformat(),
        }
    )
    billing_user = connection.scalar(
        sa.text("SELECT user_id FROM saas_tenant_onboardings WHERE id = :id"),
        {"id": billing_onboarding},
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_self_service_events ("
            "id, aggregate_type, aggregate_id, tenant_id, user_id, sequence, event_type, "
            "from_status, to_status, facts, facts_hash, previous_hash, event_hash, "
            "occurred_at) VALUES ("
            ":id, 'tenant_onboarding', :aggregate_id, :tenant_id, :user_id, 1, "
            "'tenant_onboarding.legacy_runtime_target_observed', 'billing_ready', "
            "'billing_ready', CAST(:facts AS json), :facts_hash, :previous_hash, "
            ":event_hash, :occurred_at)"
        ),
        {
            "id": prior_event_id,
            "aggregate_id": billing_onboarding,
            "tenant_id": billing_tenant,
            "user_id": billing_user,
            "facts": canonical_json(prior_facts),
            "facts_hash": prior_facts_hash,
            "previous_hash": "0" * 64,
            "event_hash": prior_event_hash,
            "occurred_at": now,
        },
    )
    rows["prior_self_service_event"] = prior_event_id

    # A terminal quarantine source and its exact receipt are immutable evidence
    # that p0s4 must neither delete nor rewrite while fencing the same Saga.
    quarantine_id = uuid4()
    quarantine_receipt_id = uuid4()
    quarantine_request_hash = sha256(b"legacy-quarantine-source").hexdigest()
    quarantine_error_digest = sha256(b"legacy-quarantine-error").hexdigest()
    quarantined_at = now + timedelta(minutes=1)
    quarantine_event_hash = _quarantine_event_hash(
        source_event_id=quarantine_id,
        tenant_id=billing_tenant,
        source_request_hash=quarantine_request_hash,
        source_attempt_count=1,
        action="quarantined",
        error_code="legacy_wake_rejected",
        error_digest=quarantine_error_digest,
        sequence=1,
        previous_hash="0" * 64,
        created_at=quarantined_at,
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_control_plane_outbox ("
            "id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
            "idempotency_key, request_hash, attempt_count, available_at, claimed_at, "
            "claim_token, last_error_code, last_error_digest, quarantined_at) VALUES ("
            ":id, :tenant_id, 'tenant_onboarding', :aggregate_key, "
            "'onboarding.runtime.requested', '{}'::json, :idempotency_key, "
            ":request_hash, 1, NULL, NULL, NULL, 'legacy_wake_rejected', "
            ":error_digest, :quarantined_at)"
        ),
        {
            "id": quarantine_id,
            "tenant_id": billing_tenant,
            "aggregate_key": str(billing_onboarding),
            "idempotency_key": "legacy-quarantined-wake",
            "request_hash": quarantine_request_hash,
            "error_digest": quarantine_error_digest,
            "quarantined_at": quarantined_at,
        },
    )
    connection.execute(
        sa.text(
            "INSERT INTO saas_outbox_quarantine_events ("
            "id, source_event_id, tenant_id, source_request_hash, source_attempt_count, "
            "action, error_code, error_digest, sequence, previous_hash, event_hash, "
            "created_at) VALUES ("
            ":id, :source_event_id, :tenant_id, :source_request_hash, 1, "
            "'quarantined', 'legacy_wake_rejected', :error_digest, 1, :previous_hash, "
            ":event_hash, :created_at)"
        ),
        {
            "id": quarantine_receipt_id,
            "source_event_id": quarantine_id,
            "tenant_id": billing_tenant,
            "source_request_hash": quarantine_request_hash,
            "error_digest": quarantine_error_digest,
            "previous_hash": "0" * 64,
            "event_hash": quarantine_event_hash,
            "created_at": quarantined_at,
        },
    )
    rows["quarantined_outbox"] = quarantine_id
    rows["quarantine_receipt"] = quarantine_receipt_id
    return rows


def _operation(
    *, idempotency_key: str, target_value: str = "project-a"
) -> RuntimeProviderOperation:
    provider_type = "contract-provider"
    placement_id = UUID_VALUE
    binding_revision = "binding-r1"
    binding_hash = "a" * 64
    target_json = canonical_json(
        {
            "schema_version": 1,
            "project": target_value,
            "tenant_id": str(TENANT_VALUE),
        }
    )
    target_hash = sha256(target_json.encode("utf-8")).hexdigest()
    idempotency_hash = sha256(idempotency_key.encode("utf-8")).hexdigest()
    request_hash = canonical_sha256(
        {
            "schema_version": 1,
            "operation": RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT.value,
            "provider_type": provider_type,
            "placement_id": str(placement_id),
            "binding_revision": binding_revision,
            "binding_hash": binding_hash,
            "target_hash": target_hash,
            "idempotency_hash": idempotency_hash,
        }
    )
    return RuntimeProviderOperation(
        kind=RuntimeProviderOperationKind.PROVISION_DEFAULT_PROJECT,
        provider_type=provider_type,
        placement_id=placement_id,
        binding_revision=binding_revision,
        binding_hash=binding_hash,
        target_hash=target_hash,
        idempotency_hash=idempotency_hash,
        request_hash=request_hash,
        target_json=target_json,
        idempotency_key=idempotency_key,
    )


def _response(
    operation: RuntimeProviderOperation,
    *,
    provider_request_id: str = "provider-request-1",
) -> RuntimeProviderResponse:
    attributes = {"runtime_resource_id": "runtime-project-42"}
    receipt = RuntimeProviderReceipt(
        schema_version=1,
        provider_type=operation.provider_type,
        operation=operation.kind,
        outcome=RuntimeProviderOutcome.APPLIED,
        placement_id=operation.placement_id,
        binding_revision=operation.binding_revision,
        binding_hash=operation.binding_hash,
        target_hash=operation.target_hash,
        idempotency_hash=operation.idempotency_hash,
        request_hash=operation.request_hash,
        credential_ref_hash="b" * 64,
        credential_version_hash="c" * 64,
        result_hash=canonical_sha256(attributes),
        provider_request_id=provider_request_id,
        provider_resource_id="runtime-project-42",
        observed_at=datetime(2026, 8, 25, 8, 0, tzinfo=timezone.utc),
        receipt_hash="0" * 64,
        signature_key_id="runtime-receipt-key-1",
        signature_hex="d" * 64,
    )
    receipt = replace(
        receipt,
        receipt_hash=sha256(receipt.unsigned_payload()).hexdigest(),
    )
    return RuntimeProviderResponse(receipt=receipt, attributes=attributes)


UUID_VALUE = uuid4()
TENANT_VALUE = uuid4()


def test_postgresql_journal_is_a_sealed_production_capability() -> None:
    assert PostgresqlRuntimeProviderOperationJournal.production_capable is True
    assert PostgresqlRuntimeProviderOperationJournal.durable is True
    assert PostgresqlRuntimeProviderOperationJournal.conflict_safe is True
    with pytest.raises(TypeError, match="SQLAlchemy Engine"):
        PostgresqlRuntimeProviderOperationJournal(object())  # type: ignore[arg-type]
    sqlite_engine = sa.create_engine("sqlite://", hide_parameters=True)
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        PostgresqlRuntimeProviderOperationJournal(sqlite_engine)


def test_runtime_provider_journal_migration_has_no_principal_ddl() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (
        root / "saas/control_plane/migrations/versions/p0s000000004_runtime_provider_journal.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "p0s000000003"' in source
    assert "postgresql_principals" in source
    assert "CREATE ROLE" not in source
    assert "ALTER ROLE" not in source
    assert "FORCE ROW LEVEL SECURITY" in source
    assert "saas_guard_runtime_provider_journal" in source
    assert "legacy_runtime_target_binding_unavailable" in source
    assert "tenant_onboarding.legacy_runtime_target_manual_review" in source
    assert "Active/completed and already-terminal Sagas" in source
    assert "saas_control_plane_outbox" not in source
    assert "PUBLIC TEMPORARY database authority" in source


def test_real_postgresql_runtime_provider_journal_is_atomic_and_replayable(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    principals = (root / "saas/control_plane/postgresql_principals.sql").read_text(
        encoding="utf-8"
    )
    database_authority = (root / "saas/control_plane/postgresql_database.sql").read_text(
        encoding="utf-8"
    )
    authority = (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
    owner_engine = sa.create_engine(isolated_postgres_url, hide_parameters=True)
    database_url = sa.engine.make_url(isolated_postgres_url)
    database_name = database_url.database
    assert database_name is not None
    quoted_database = owner_engine.dialect.identifier_preparer.quote(database_name)
    other_database_name = f"runtime_journal_other_{uuid4().hex[:12]}"
    quoted_other_database = owner_engine.dialect.identifier_preparer.quote(other_database_name)
    foreign_data_wrapper_name = f"runtime_journal_fdw_{uuid4().hex[:12]}"
    foreign_server_name = f"runtime_journal_server_{uuid4().hex[:12]}"
    quoted_foreign_data_wrapper = owner_engine.dialect.identifier_preparer.quote(
        foreign_data_wrapper_name
    )
    quoted_foreign_server = owner_engine.dialect.identifier_preparer.quote(foreign_server_name)
    cluster_admin_engine = sa.create_engine(
        isolated_postgres_url,
        hide_parameters=True,
        isolation_level="AUTOCOMMIT",
    )
    with owner_engine.connect() as connection:
        database_owner = str(connection.scalar(sa.text("SELECT current_user")))
    quoted_database_owner = owner_engine.dialect.identifier_preparer.quote(database_owner)
    login_role = f"runtime_journal_login_{uuid4().hex[:12]}"
    login_password = f"journal-{uuid4().hex}-{uuid4().hex}"
    quoted_login = owner_engine.dialect.identifier_preparer.quote(login_role)
    journal_engine: sa.Engine | None = None
    assumed_engine: sa.Engine | None = None
    try:
        with owner_engine.begin() as connection:
            # The fixture applies the production database boundary. Reintroduce
            # the unsafe PostgreSQL default to prove p0s4 rejects out-of-order
            # deployments before any schema or data mutation.
            connection.exec_driver_sql(f"GRANT TEMPORARY ON DATABASE {quoted_database} TO PUBLIC")
            connection.exec_driver_sql(principals)
            command.upgrade(_migration_config(connection), "p0s000000003")
            legacy_rows = _seed_legacy_runtime_target_migration_rows(connection)
        rejected_connection = owner_engine.connect()
        rejected_transaction = rejected_connection.begin()
        try:
            with pytest.raises(RuntimeError, match="PUBLIC TEMPORARY database authority"):
                command.upgrade(_migration_config(rejected_connection), "head")
        finally:
            rejected_transaction.rollback()
            rejected_connection.close()
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(database_authority)
        with owner_engine.begin() as connection:
            command.upgrade(_migration_config(connection), "head")
            connection.exec_driver_sql(authority)
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_login} LOGIN PASSWORD '{login_password}' "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
                "NOBYPASSRLS INHERIT CONNECTION LIMIT -1"
            )
            connection.exec_driver_sql(f"ALTER ROLE {quoted_login} SET search_path = public")
            connection.exec_driver_sql(
                f"GRANT {_JOURNAL_ROLE} TO {quoted_login} "
                "WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_database} TO {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"CREATE FOREIGN DATA WRAPPER {quoted_foreign_data_wrapper} NO HANDLER"
            )
            connection.exec_driver_sql(
                f"CREATE SERVER {quoted_foreign_server} "
                f"FOREIGN DATA WRAPPER {quoted_foreign_data_wrapper}"
            )
        with cluster_admin_engine.connect() as connection:
            connection.exec_driver_sql(
                f"CREATE DATABASE {quoted_other_database} TEMPLATE template0"
            )

        with owner_engine.begin() as connection:
            manual_rows = connection.execute(
                sa.text(
                    "SELECT id, status, version, failure_stage, compensation_cursor, "
                    "claim_token, claimed_at, lease_expires_at, last_error_code, "
                    "last_error_detail, runtime_target_snapshot, runtime_request_hash "
                    "FROM saas_tenant_onboardings WHERE id = ANY(:ids) ORDER BY id"
                ),
                {
                    "ids": [
                        legacy_rows[status]
                        for status in (
                            "billing_ready",
                            "runtime_ready",
                            "project_ready",
                            "compensating",
                        )
                    ]
                },
            ).all()
            assert len(manual_rows) == 4
            expected_failure = {
                legacy_rows["billing_ready"]: ("billing_ready", "runtime"),
                legacy_rows["runtime_ready"]: ("runtime_ready", "project"),
                legacy_rows["project_ready"]: ("project_ready", "project"),
                legacy_rows["compensating"]: ("runtime_ready", "project"),
            }
            for row in manual_rows:
                assert row.status == "manual_review"
                assert row.version == 8
                assert (row.failure_stage, row.compensation_cursor) == expected_failure[row.id]
                assert row.claim_token is None
                assert row.claimed_at is None
                assert row.lease_expires_at is None
                assert row.last_error_code == "legacy_runtime_target_binding_unavailable"
                assert (
                    row.last_error_detail
                    == "legacy runtime target requires operator reconciliation"
                )
                assert row.runtime_target_snapshot["schema_version"] == 1
                assert "provider_binding" not in row.runtime_target_snapshot
                assert len(row.runtime_request_hash) == 64
            migration_events = connection.execute(
                sa.text(
                    "SELECT aggregate_id, sequence, event_type, from_status, to_status, "
                    "facts, facts_hash, previous_hash, event_hash, occurred_at "
                    "FROM saas_self_service_events WHERE aggregate_id = ANY(:ids) "
                    "ORDER BY aggregate_id, sequence"
                ),
                {
                    "ids": [
                        legacy_rows[status]
                        for status in (
                            "billing_ready",
                            "runtime_ready",
                            "project_ready",
                            "compensating",
                        )
                    ]
                },
            ).all()
            by_aggregate: dict[UUID, list[sa.Row[tuple[object, ...]]]] = {}
            for event in migration_events:
                by_aggregate.setdefault(event.aggregate_id, []).append(event)
            assert set(by_aggregate) == {
                legacy_rows[status]
                for status in (
                    "billing_ready",
                    "runtime_ready",
                    "project_ready",
                    "compensating",
                )
            }
            for aggregate_id, events in by_aggregate.items():
                migration_event = events[-1]
                assert migration_event.event_type == (
                    "tenant_onboarding.legacy_runtime_target_manual_review"
                )
                assert migration_event.to_status == "manual_review"
                assert migration_event.facts == {
                    "error_code": "legacy_runtime_target_binding_unavailable",
                    "migration_revision": "p0s000000004",
                    "provider_binding_action": "not_rebound",
                    "recovery_wake_action": "preserved_stale_cas",
                    "runtime_target_schema_version": 1,
                }
                assert migration_event.facts_hash == canonical_sha256(migration_event.facts)
                if len(events) == 1:
                    assert migration_event.sequence == 1
                    assert migration_event.previous_hash == "0" * 64
                else:
                    assert aggregate_id == legacy_rows["billing_ready"]
                    assert migration_event.sequence == events[-2].sequence + 1
                    assert migration_event.previous_hash == events[-2].event_hash
                assert migration_event.event_hash == canonical_sha256(
                    {
                        "aggregate_type": "tenant_onboarding",
                        "aggregate_id": str(aggregate_id),
                        "sequence": migration_event.sequence,
                        "event_type": migration_event.event_type,
                        "from_status": migration_event.from_status,
                        "to_status": migration_event.to_status,
                        "facts_hash": migration_event.facts_hash,
                        "previous_hash": migration_event.previous_hash,
                        "occurred_at": migration_event.occurred_at.astimezone(
                            timezone.utc
                        ).isoformat(),
                    }
                )
            affected_ids = [
                str(legacy_rows[status])
                for status in (
                    "billing_ready",
                    "runtime_ready",
                    "project_ready",
                    "compensating",
                )
            ]
            preserved_wakes = connection.execute(
                sa.text(
                    "SELECT aggregate_key, payload, available_at, claimed_at, claim_token "
                    "FROM saas_control_plane_outbox "
                    "WHERE aggregate_key = ANY(:ids) AND published_at IS NULL "
                    "AND quarantined_at IS NULL "
                    "ORDER BY aggregate_key"
                ),
                {"ids": affected_ids},
            ).all()
            assert len(preserved_wakes) == 4
            for wake in preserved_wakes:
                assert wake.payload["version"] == 7
                assert wake.payload["expected_status"] in {
                    "billing_ready",
                    "runtime_ready",
                    "project_ready",
                    "compensating",
                }
                assert wake.available_at == _LEGACY_SEED_TIME
                assert wake.claimed_at is None
                assert wake.claim_token is None
            quarantine_source = connection.execute(
                sa.text(
                    "SELECT id, available_at, claimed_at, claim_token, published_at, "
                    "quarantined_at, last_error_code, last_error_digest, request_hash, "
                    "attempt_count FROM saas_control_plane_outbox WHERE id = :id"
                ),
                {"id": legacy_rows["quarantined_outbox"]},
            ).one()
            quarantine_receipt = connection.execute(
                sa.text(
                    "SELECT id, source_event_id, source_request_hash, "
                    "source_attempt_count, error_code, error_digest, sequence, "
                    "previous_hash, event_hash, created_at "
                    "FROM saas_outbox_quarantine_events WHERE id = :id"
                ),
                {"id": legacy_rows["quarantine_receipt"]},
            ).one()
            assert quarantine_source.available_at is None
            assert quarantine_source.claimed_at is None
            assert quarantine_source.claim_token is None
            assert quarantine_source.published_at is None
            assert quarantine_source.quarantined_at == _LEGACY_SEED_TIME + timedelta(minutes=1)
            assert quarantine_source.last_error_code == "legacy_wake_rejected"
            assert quarantine_source.attempt_count == 1
            assert quarantine_receipt.source_event_id == quarantine_source.id
            assert quarantine_receipt.source_request_hash == quarantine_source.request_hash
            assert quarantine_receipt.source_attempt_count == quarantine_source.attempt_count
            assert quarantine_receipt.error_code == quarantine_source.last_error_code
            assert quarantine_receipt.error_digest == quarantine_source.last_error_digest
            assert quarantine_receipt.sequence == 1
            assert quarantine_receipt.previous_hash == "0" * 64
            assert quarantine_receipt.created_at == quarantine_source.quarantined_at
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE id = :id AND published_at IS NOT NULL"
                    ),
                    {"id": legacy_rows["published_outbox"]},
                )
                == 1
            )

            stale_wake = connection.execute(
                sa.text(
                    "SELECT event_type, payload FROM saas_control_plane_outbox "
                    "WHERE aggregate_key = :aggregate_key AND published_at IS NULL "
                    "AND quarantined_at IS NULL ORDER BY created_at LIMIT 1"
                ),
                {"aggregate_key": str(legacy_rows["billing_ready"])},
            ).one()
            active = connection.execute(
                sa.text(
                    "SELECT status, version, last_error_code, runtime_target_snapshot "
                    "FROM saas_tenant_onboardings WHERE id = :id"
                ),
                {"id": legacy_rows["active"]},
            ).one()
            assert active.status == "active"
            assert active.version == 7
            assert active.last_error_code is None
            assert active.runtime_target_snapshot["schema_version"] == 1
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE aggregate_key = :id AND published_at IS NULL"
                    ),
                    {"id": str(legacy_rows["active"])},
                )
                == 1
            )

            forced_tables = set(
                connection.execute(
                    sa.text(
                        "SELECT relname FROM pg_class WHERE relrowsecurity "
                        "AND relforcerowsecurity AND relname = ANY(:tables)"
                    ),
                    {"tables": sorted(CONTROL_PLANE_RLS_TABLES)},
                ).scalars()
            )
            assert len(CONTROL_PLANE_RLS_TABLES) == 111
            assert forced_tables == CONTROL_PLANE_RLS_TABLES
            role_facts = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, "
                    "rolreplication, rolbypassrls, rolinherit, rolconnlimit, rolconfig "
                    "FROM pg_roles WHERE rolname = :role"
                ),
                {"role": _JOURNAL_ROLE},
            ).one()
            assert role_facts == (
                False,
                False,
                False,
                False,
                False,
                False,
                True,
                -1,
                None,
            )

            table_privileges = set(
                connection.execute(
                    sa.text(
                        "SELECT privilege_type FROM information_schema.table_privileges "
                        "WHERE table_schema = 'public' AND table_name = :table "
                        "AND grantee = :role"
                    ),
                    {"table": _TABLE, "role": _JOURNAL_ROLE},
                ).scalars()
            )
            column_privileges = set(
                connection.execute(
                    sa.text(
                        "SELECT column_name, privilege_type "
                        "FROM information_schema.column_privileges "
                        "WHERE table_schema = 'public' AND table_name = :table "
                        "AND grantee = :role"
                    ),
                    {"table": _TABLE, "role": _JOURNAL_ROLE},
                ).all()
            )
            assert table_privileges == {"SELECT"}
            assert {
                column for column, privilege in column_privileges if privilege == "INSERT"
            } == {
                "id",
                "provider_type",
                "operation_kind",
                "placement_id",
                "binding_revision",
                "binding_hash",
                "target_hash",
                "idempotency_hash",
                "request_hash",
            }
            assert {
                column for column, privilege in column_privileges if privilege == "UPDATE"
            } == {
                "receipt_hash",
                "attributes_hash",
                "response_hash",
                "receipt_json",
                "attributes_json",
            }
            forbidden_relations = connection.scalar(
                sa.text(
                    "SELECT count(*) FROM pg_class AS relation "
                    "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                    "WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p') "
                    "AND relation.relname LIKE 'saas_%' AND relation.relname <> :table AND ("
                    "has_table_privilege(:role, relation.oid, "
                    "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR "
                    "has_any_column_privilege(:role, relation.oid, "
                    "'SELECT,INSERT,UPDATE,REFERENCES'))"
                ),
                {"table": _TABLE, "role": _JOURNAL_ROLE},
            )
            assert forbidden_relations == 0

        workflow_sessions = sessionmaker(owner_engine, expire_on_commit=False)
        provider_must_not_run = _ProviderMustNotRun()
        workflow = TenantOnboardingWorkflow(
            workflow_sessions,
            runtime=cast(RuntimePartitionProvisioner, provider_must_not_run),
            execution_session_factory=cast(sessionmaker[Session], workflow_sessions),
        )
        stale_result = workflow.handle_event(
            event_type=stale_wake.event_type,
            payload=dict(stale_wake.payload),
        )
        assert stale_result.status == "manual_review"
        assert stale_result.version == 8
        assert stale_result.replayed is True
        assert provider_must_not_run.calls == 0

        journal_url = database_url.set(
            host=database_url.host or "127.0.0.1",
            username=login_role,
            password=login_password,
        )
        journal_engine = sa.create_engine(
            journal_url,
            hide_parameters=True,
            pool_size=12,
            max_overflow=0,
        )
        journal = PostgresqlRuntimeProviderOperationJournal(journal_engine)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT USAGE ON FOREIGN SERVER {quoted_foreign_server} TO {quoted_login}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE USAGE ON FOREIGN SERVER {quoted_foreign_server} FROM {quoted_login}"
            )
            connection.exec_driver_sql(
                f"GRANT USAGE ON FOREIGN SERVER {quoted_foreign_server} TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE USAGE ON FOREIGN SERVER {quoted_foreign_server} FROM {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        journal = PostgresqlRuntimeProviderOperationJournal(journal_engine)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"GRANT {_JOURNAL_ROLE} TO {quoted_login} WITH SET TRUE")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="membership is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"GRANT {_JOURNAL_ROLE} TO {quoted_login} WITH SET FALSE")
        journal_engine.dispose()
        PostgresqlRuntimeProviderOperationJournal(journal_engine)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT CREATE ON DATABASE {quoted_database} TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE CREATE ON DATABASE {quoted_database} FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT TEMPORARY ON DATABASE {quoted_database} TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="must not create temporary objects"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE TEMPORARY ON DATABASE {quoted_database} FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_database} TO {_JOURNAL_ROLE} WITH GRANT OPTION"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE GRANT OPTION FOR CONNECT ON DATABASE {quoted_database} "
                f"FROM {_JOURNAL_ROLE} CASCADE"
            )
        journal_engine.dispose()
        PostgresqlRuntimeProviderOperationJournal(journal_engine)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_other_database} TO {quoted_login}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE CONNECT ON DATABASE {quoted_other_database} FROM {quoted_login}"
            )
            connection.exec_driver_sql(
                f"ALTER DATABASE {quoted_other_database} OWNER TO {quoted_login}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER DATABASE {quoted_other_database} OWNER TO {quoted_database_owner}"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted_other_database} TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE CONNECT ON DATABASE {quoted_other_database} FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"ALTER DATABASE {quoted_other_database} OWNER TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER DATABASE {quoted_other_database} OWNER TO {quoted_database_owner}"
            )
        journal_engine.dispose()
        PostgresqlRuntimeProviderOperationJournal(journal_engine)

        with pytest.raises(RuntimeError):
            PostgresqlRuntimeProviderOperationJournal(owner_engine)
        assumed_url = database_url.update_query_dict({"options": f"-c role={login_role}"})
        assumed_engine = sa.create_engine(assumed_url, hide_parameters=True)
        with pytest.raises(RuntimeError, match="assumed role"):
            PostgresqlRuntimeProviderOperationJournal(assumed_engine)

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"GRANT saas_app TO {quoted_login}")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="membership is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE saas_app FROM {quoted_login}")
            connection.exec_driver_sql(f"GRANT SELECT (id) ON saas_tenants TO {quoted_login}")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE SELECT (id) ON saas_tenants FROM {quoted_login}")
            connection.exec_driver_sql(
                f"GRANT {_JOURNAL_ROLE} TO {quoted_login} WITH ADMIN OPTION"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="membership is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE ADMIN OPTION FOR {_JOURNAL_ROLE} FROM {quoted_login}"
            )
            connection.exec_driver_sql(
                f"ALTER ROLE {quoted_login} SET search_path = pg_catalog, public"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="only public search_path"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER ROLE {quoted_login} SET search_path = public")
        journal_engine.dispose()

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"GRANT TEMPORARY ON DATABASE {quoted_database} TO {quoted_login}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="must not create temporary objects"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE TEMPORARY ON DATABASE {quoted_database} FROM {quoted_login}"
            )
            connection.exec_driver_sql(f"GRANT TEMPORARY ON DATABASE {quoted_database} TO PUBLIC")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="must not create temporary objects"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE TEMPORARY ON DATABASE {quoted_database} FROM PUBLIC"
            )
        journal_engine.dispose()

        shadow_schema = f"journal_shadow_{uuid4().hex[:12]}"
        quoted_shadow = owner_engine.dialect.identifier_preparer.quote(shadow_schema)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"CREATE SCHEMA {quoted_shadow}")
            connection.exec_driver_sql(f"GRANT USAGE ON SCHEMA {quoted_shadow} TO {quoted_login}")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE USAGE ON SCHEMA {quoted_shadow} FROM {quoted_login}"
            )
            connection.exec_driver_sql(f"ALTER SCHEMA {quoted_shadow} OWNER TO {quoted_login}")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="direct database authority"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP SCHEMA {quoted_shadow}")
        journal_engine.dispose()

        base_shadow = f"journal_base_shadow_{uuid4().hex[:12]}"
        quoted_base_shadow = owner_engine.dialect.identifier_preparer.quote(base_shadow)
        with owner_engine.begin() as connection:
            owner_role = str(connection.scalar(sa.text("SELECT current_user")))
            quoted_owner = owner_engine.dialect.identifier_preparer.quote(owner_role)
            connection.exec_driver_sql(f"CREATE SCHEMA {quoted_base_shadow}")
            connection.exec_driver_sql(
                f"CREATE FUNCTION {quoted_base_shadow}.elevated_probe() RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog "
                "AS 'SELECT 1'"
            )
            connection.exec_driver_sql(
                f"REVOKE ALL ON FUNCTION {quoted_base_shadow}.elevated_probe() FROM PUBLIC"
            )
            connection.exec_driver_sql(f"CREATE SEQUENCE {quoted_base_shadow}.provider_sequence")
            connection.exec_driver_sql(
                f"CREATE VIEW {quoted_base_shadow}.provider_view AS SELECT 1 AS value"
            )
            connection.exec_driver_sql(
                f"CREATE TYPE {quoted_base_shadow}.provider_marker AS ENUM ('marker')"
            )
            connection.exec_driver_sql(
                f"GRANT USAGE ON SCHEMA {quoted_base_shadow} TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE USAGE ON SCHEMA {quoted_base_shadow} FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT EXECUTE ON FUNCTION {quoted_base_shadow}.elevated_probe() "
                f"TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE EXECUTE ON FUNCTION {quoted_base_shadow}.elevated_probe() "
                f"FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT SELECT ON SEQUENCE {quoted_base_shadow}.provider_sequence "
                f"TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE SELECT ON SEQUENCE {quoted_base_shadow}.provider_sequence "
                f"FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT SELECT ON {quoted_base_shadow}.provider_view TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE SELECT ON {quoted_base_shadow}.provider_view FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"GRANT USAGE ON TYPE {quoted_base_shadow}.provider_marker TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE USAGE ON TYPE {quoted_base_shadow}.provider_marker FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(
                f"ALTER SCHEMA {quoted_base_shadow} OWNER TO {_JOURNAL_ROLE}"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="base role authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER SCHEMA {quoted_base_shadow} OWNER TO {quoted_owner}"
            )
            connection.exec_driver_sql(f"DROP SCHEMA {quoted_base_shadow} CASCADE")
        journal_engine.dispose()

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"GRANT DELETE ON {_TABLE} TO PUBLIC")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="effective table authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE DELETE ON {_TABLE} FROM PUBLIC")
            connection.exec_driver_sql(f"GRANT UPDATE (request_hash) ON {_TABLE} TO PUBLIC")
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="effective column authority is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"REVOKE UPDATE (request_hash) ON {_TABLE} FROM PUBLIC")
        journal_engine.dispose()

        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER TABLE {_TABLE} DISABLE TRIGGER trg_runtime_provider_journal_immutable"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="immutability trigger is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER TABLE {_TABLE} ENABLE TRIGGER trg_runtime_provider_journal_immutable"
            )
            connection.exec_driver_sql(
                "ALTER FUNCTION saas_guard_runtime_provider_journal() SECURITY DEFINER"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="immutability trigger is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER FUNCTION saas_guard_runtime_provider_journal() SECURITY INVOKER"
            )
            original_function = connection.scalar(
                sa.text(
                    "SELECT pg_get_functiondef("
                    "'public.saas_guard_runtime_provider_journal()'::regprocedure)"
                )
            )
            assert isinstance(original_function, str)
            connection.exec_driver_sql(
                "CREATE OR REPLACE FUNCTION saas_guard_runtime_provider_journal() "
                "RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER "
                "SET search_path = pg_catalog AS $$ BEGIN RETURN NEW; END; $$"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="immutability trigger is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(original_function)
            connection.exec_driver_sql(
                f"ALTER TABLE {_TABLE} DROP CONSTRAINT ck_runtime_provider_journal_provider"
            )
        journal_engine.dispose()
        with pytest.raises(RuntimeError, match="constraint set is unsafe"):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER TABLE {_TABLE} ADD CONSTRAINT "
                "ck_runtime_provider_journal_provider "
                "CHECK (length(provider_type) > 0)"
            )
            connection.exec_driver_sql(f"ALTER TABLE {_TABLE} ADD COLUMN schema_drift text")
        journal_engine.dispose()
        with pytest.raises(
            RuntimeError,
            match=r"(column signature|effective column authority) is unsafe",
        ):
            PostgresqlRuntimeProviderOperationJournal(journal_engine)
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER TABLE {_TABLE} DROP COLUMN schema_drift")
        journal_engine.dispose()
        journal = PostgresqlRuntimeProviderOperationJournal(journal_engine)

        committed_fence_operation = _operation(idempotency_key="shared-read-scope-committed-fence")
        with shared_read_scope():
            committed_fence = journal.begin(committed_fence_operation)
            assert committed_fence.is_new is True
            # The Provider can run on another connection immediately after
            # begin() returns, so that connection must already see the fence.
            with journal_engine.connect() as observer:
                assert (
                    observer.scalar(
                        sa.text(
                            f"SELECT count(*) FROM {_TABLE} WHERE request_hash = :request_hash"
                        ),
                        {"request_hash": committed_fence_operation.request_hash},
                    )
                    == 1
                )

        operation = _operation(idempotency_key="raw-idempotency-secret")

        with ThreadPoolExecutor(max_workers=12) as executor:
            entries = list(executor.map(lambda _: journal.begin(operation), range(12)))
        assert sum(entry.is_new for entry in entries) == 1
        assert {entry.request_hash for entry in entries} == {operation.request_hash}
        assert all(entry.response is None for entry in entries)

        conflicting_operation = _operation(
            idempotency_key="raw-idempotency-secret",
            target_value="project-b",
        )
        with pytest.raises(RuntimeProviderError) as conflict:
            journal.begin(conflicting_operation)
        assert conflict.value.disposition is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT

        response = _response(operation)

        tampered_operation = _operation(idempotency_key="tampered-pending-fence")
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    f"INSERT INTO {_TABLE} ("
                    "id, provider_type, operation_kind, placement_id, binding_revision, "
                    "binding_hash, target_hash, idempotency_hash, request_hash) VALUES ("
                    ":id, :provider_type, :operation_kind, :placement_id, "
                    ":binding_revision, :binding_hash, :target_hash, "
                    ":idempotency_hash, :request_hash)"
                ),
                {
                    "id": uuid4(),
                    "provider_type": tampered_operation.provider_type,
                    "operation_kind": tampered_operation.kind.value,
                    "placement_id": uuid4(),
                    "binding_revision": tampered_operation.binding_revision,
                    "binding_hash": tampered_operation.binding_hash,
                    "target_hash": tampered_operation.target_hash,
                    "idempotency_hash": tampered_operation.idempotency_hash,
                    "request_hash": tampered_operation.request_hash,
                },
            )
        with pytest.raises(RuntimeProviderError) as tampered_lookup:
            journal.lookup(tampered_operation)
        assert (
            tampered_lookup.value.disposition
            is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT
        )
        with pytest.raises(RuntimeProviderError) as tampered_record:
            journal.record_verified(
                operation=tampered_operation,
                response=_response(tampered_operation),
            )
        assert (
            tampered_record.value.disposition
            is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT
        )

        # Model an acknowledgement loss immediately after the durable commit.
        with pytest.raises(ConnectionError, match="acknowledgement lost"):
            journal.record_verified(operation=operation, response=response)
            raise ConnectionError("acknowledgement lost")

        rebuilt = PostgresqlRuntimeProviderOperationJournal(journal_engine)
        replayed = rebuilt.lookup(operation)
        assert replayed is not None and replayed.is_new is False
        assert replayed.response == response
        rebuilt.record_verified(operation=operation, response=response)

        conflicting_response = _response(
            operation,
            provider_request_id="provider-request-conflict",
        )
        with pytest.raises(RuntimeProviderError) as receipt_conflict:
            rebuilt.record_verified(
                operation=operation,
                response=conflicting_response,
            )
        assert (
            receipt_conflict.value.disposition
            is RuntimeProviderFailureDisposition.IDEMPOTENCY_CONFLICT
        )

        with journal_engine.connect() as connection:
            stored = connection.execute(
                sa.text(
                    "SELECT idempotency_hash, request_hash, receipt_json, attributes_json "
                    f"FROM {_TABLE} WHERE request_hash = :request_hash"
                ),
                {"request_hash": operation.request_hash},
            ).one()
            assert stored.idempotency_hash == operation.idempotency_hash
            assert stored.request_hash == operation.request_hash
            assert "raw-idempotency-secret" not in repr(stored)
            assert "provider-request-1" in stored.receipt_json

        with pytest.raises(sa.exc.DBAPIError), journal_engine.begin() as connection:
            connection.execute(
                sa.text(
                    f"UPDATE {_TABLE} SET response_hash = response_hash "
                    "WHERE request_hash = :request_hash"
                ),
                {"request_hash": operation.request_hash},
            )
        with journal_engine.connect() as connection:
            privileges = connection.execute(
                sa.text(
                    "SELECT has_table_privilege(current_user, :table, 'SELECT'), "
                    "has_table_privilege(current_user, :table, 'INSERT'), "
                    "has_table_privilege(current_user, :table, 'UPDATE'), "
                    "has_table_privilege(current_user, :table, 'DELETE'), "
                    "has_table_privilege(current_user, :table, 'TRUNCATE'), "
                    "has_table_privilege(current_user, :table, 'TRIGGER')"
                ),
                {"table": f"public.{_TABLE}"},
            ).one()
            assert privileges == (True, False, False, False, False, False)

        # Both the irreversible v1 fail-closed transition and a recorded
        # Provider receipt independently block downgrade.  Each rejection must
        # roll its temporary NO FORCE posture back with the Alembic transaction.
        migration_connection = owner_engine.connect()
        migration_transaction = migration_connection.begin()
        try:
            with pytest.raises(RuntimeError, match="fail-closed legacy Runtime target"):
                command.downgrade(
                    _migration_config(migration_connection),
                    "p0s000000003",
                )
        finally:
            migration_transaction.rollback()
            migration_connection.close()
        with owner_engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE saas_tenant_onboardings SET last_error_code = NULL "
                    "WHERE last_error_code = 'legacy_runtime_target_binding_unavailable'"
                )
            )
        migration_connection = owner_engine.connect()
        migration_transaction = migration_connection.begin()
        try:
            with pytest.raises(RuntimeError, match="durable Runtime Provider"):
                command.downgrade(
                    _migration_config(migration_connection),
                    "p0s000000003",
                )
        finally:
            migration_transaction.rollback()
            migration_connection.close()
        with owner_engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == "p0s000000011"
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT relforcerowsecurity FROM pg_class "
                        f"WHERE oid = 'public.{_TABLE}'::regclass"
                    )
                )
                is True
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT relforcerowsecurity FROM pg_class "
                        "WHERE oid = 'public.saas_tenant_onboardings'::regclass"
                    )
                )
                is True
            )
    finally:
        if journal_engine is not None:
            journal_engine.dispose()
        if assumed_engine is not None:
            assumed_engine.dispose()
        with cluster_admin_engine.connect() as connection:
            connection.exec_driver_sql(
                f"ALTER DATABASE {quoted_other_database} OWNER TO {quoted_database_owner}"
            )
            connection.exec_driver_sql(
                f"DROP DATABASE IF EXISTS {quoted_other_database} WITH (FORCE)"
            )
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f"REVOKE CONNECT ON DATABASE {quoted_database} FROM {_JOURNAL_ROLE}"
            )
            connection.exec_driver_sql(f"DROP SERVER IF EXISTS {quoted_foreign_server} CASCADE")
            connection.exec_driver_sql(
                f"DROP FOREIGN DATA WRAPPER IF EXISTS {quoted_foreign_data_wrapper} CASCADE"
            )
            login_exists = connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
                {"role": login_role},
            )
            if login_exists:
                connection.exec_driver_sql(f"DROP OWNED BY {quoted_login}")
                connection.exec_driver_sql(f"DROP ROLE {quoted_login}")
        cluster_admin_engine.dispose()
        owner_engine.dispose()
