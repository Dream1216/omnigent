"""Run a disposable PostgreSQL logical backup and isolated-restore contract.

This is deliberately CI evidence, not production recovery evidence. It proves that
an exact migrated PostgreSQL database can be dumped, restored into a different
database, replay post-backup deletion/revocation facts, retain forced RLS, and match
selected content hashes. It does not exercise WAL/PITR, another failure domain,
multi-AZ failover, external KMS/object storage, or production data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import URL, make_url

from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.runtime_rls import install_runtime_rls, load_runtime_rls_contract, verify_runtime_rls

_DATABASE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_SELECTED_HASH_TABLES = (
    "alembic_version",
    "saas_alembic_version",
    "users",
    "saas_global_users",
    "saas_identity_connections",
    "saas_auth_sessions",
    "saas_platform_staff_principals",
    "saas_platform_role_assignments",
    "saas_platform_auth_sessions",
    "saas_platform_tenant_projections",
    "saas_platform_user_projections",
    "saas_tenants",
    "saas_spaces",
    "saas_runtime_placements",
    "saas_tenant_memberships",
    "saas_space_memberships",
    "saas_projects",
    "saas_tasks",
    "saas_runs",
    "saas_runner_pools",
    "saas_runner_registrations",
    "saas_run_dispatches",
    "saas_capability_tokens",
    "saas_runner_certificates",
    "saas_service_accounts",
    "saas_api_credentials",
    "saas_public_api_mutation_receipts",
    "saas_public_api_rate_limits",
    "saas_enterprise_groups",
    "saas_enterprise_group_memberships",
    "saas_enterprise_custom_roles",
    "saas_enterprise_group_role_assignments",
    "saas_enterprise_access_preflights",
    "saas_enterprise_scim_directories",
    "saas_enterprise_scim_users",
    "saas_enterprise_scim_groups",
    "saas_enterprise_scim_events",
    "saas_privacy_legal_holds",
    "saas_privacy_deletion_manifests",
    "saas_privacy_identity_tombstones",
    "saas_privacy_approval_bindings",
    "saas_privacy_deletion_work_items",
    "saas_privacy_deletion_attempts",
    "saas_privacy_evidence_attestations",
    "saas_privacy_backup_retention_items",
    "saas_approval_work_items",
    "saas_approval_delegations",
    "saas_notification_templates",
    "saas_notification_preferences",
    "saas_notification_deliveries",
    "saas_notification_delivery_attempts",
    "saas_operation_batches",
    "saas_operation_batch_items",
    "saas_billing_subscriptions",
    "saas_pricing_snapshots",
    "saas_billing_entitlements",
    "saas_usage_events",
    "saas_billing_balances",
    "saas_billing_reservations",
    "saas_customer_ledger_entries",
    "saas_provider_cost_entries",
    "saas_billing_reconciliation_batches",
    "saas_billing_reconciliation_mismatches",
    "saas_billing_period_closes",
    "saas_billing_metering_receipts",
    "saas_control_plane_outbox",
)


class PostgreSqlRestoreContractError(RuntimeError):
    """Raised when the disposable restore cannot prove the CI contract."""


@dataclass(frozen=True, slots=True)
class PostgreSqlEndpoint:
    """Non-secret PostgreSQL connection coordinates plus an isolated password."""

    drivername: str
    username: str
    password: str | None
    host: str
    port: int
    admin_database: str

    @classmethod
    def parse(cls, raw_url: str) -> PostgreSqlEndpoint:
        """Parse a TCP PostgreSQL URL and reject ambiguous or unsafe targets."""

        url = make_url(raw_url)
        if not url.drivername.startswith("postgresql"):
            raise PostgreSqlRestoreContractError("admin URL must use PostgreSQL")
        if not url.username or not url.host or not url.port or not url.database:
            raise PostgreSqlRestoreContractError(
                "admin URL must declare username, TCP host, port, and database"
            )
        if url.query:
            raise PostgreSqlRestoreContractError("admin URL query parameters are not allowed")
        return cls(
            drivername=url.drivername,
            username=url.username,
            password=url.password,
            host=url.host,
            port=url.port,
            admin_database=url.database,
        )

    def sqlalchemy_url(self, database: str) -> URL:
        _require_database_name(database)
        return URL.create(
            self.drivername,
            username=self.username,
            password=self.password,
            host=self.host,
            port=self.port,
            database=database,
        )


def _require_database_name(database: str) -> None:
    if _DATABASE_NAME.fullmatch(database) is None:
        raise PostgreSqlRestoreContractError("unsafe generated database name")


def _database_name(kind: str) -> str:
    return f"omnigent_{kind}_{uuid4().hex[:20]}"


def _admin_engine(endpoint: PostgreSqlEndpoint) -> sa.Engine:
    return sa.create_engine(
        endpoint.sqlalchemy_url(endpoint.admin_database),
        isolation_level="AUTOCOMMIT",
        poolclass=sa.pool.NullPool,
    )


def _create_database(endpoint: PostgreSqlEndpoint, database: str) -> None:
    _require_database_name(database)
    engine = _admin_engine(endpoint)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database}"')
    finally:
        engine.dispose()


def _drop_database(endpoint: PostgreSqlEndpoint, database: str) -> None:
    _require_database_name(database)
    engine = _admin_engine(endpoint)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
    finally:
        engine.dispose()


def _alembic_upgrade(connection: sa.Connection, config_path: Path, script_path: Path) -> None:
    config = Config(config_path)
    config.set_main_option("script_location", str(script_path))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


def _migrate_source(repo: Path, endpoint: PostgreSqlEndpoint, database: str) -> None:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        # Alembic owns this boundary because official migrations may enter an
        # autocommit block for PostgreSQL concurrent index creation.
        with engine.connect() as connection:
            _alembic_upgrade(
                connection,
                repo / "omnigent/db/alembic.ini",
                repo / "omnigent/db/migrations",
            )
            _alembic_upgrade(
                connection,
                repo / "saas/control_plane/alembic.ini",
                repo / "saas/control_plane/migrations",
            )

        with engine.begin() as connection:
            install_runtime_rls(connection)
            connection.exec_driver_sql(
                (repo / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql(
                (repo / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
            )
    finally:
        engine.dispose()


def _seed_source(endpoint: PostgreSqlEndpoint, database: str) -> dict[str, str | int]:
    identifiers: dict[str, str | int] = {
        "actor_a": "10000000-0000-4000-8000-000000000001",
        "actor_b": "10000000-0000-4000-8000-000000000002",
        "approver_a": "10000000-0000-4000-8000-000000000003",
        "approver_b": "10000000-0000-4000-8000-000000000004",
        "tenant_a": "20000000-0000-4000-8000-000000000001",
        "tenant_b": "20000000-0000-4000-8000-000000000002",
        "space_a": "30000000-0000-4000-8000-000000000001",
        "space_b": "30000000-0000-4000-8000-000000000002",
        "project_a": "90000000-0000-4000-8000-000000000001",
        "project_b": "90000000-0000-4000-8000-000000000002",
        "runtime_placement": "95000000-0000-4000-8000-000000000001",
        "runner_pool": "96000000-0000-4000-8000-000000000001",
        "runner_a": "97000000-0000-4000-8000-000000000001",
        "runner_b": "97000000-0000-4000-8000-000000000002",
        "task_a": "98000000-0000-4000-8000-000000000001",
        "task_b": "98000000-0000-4000-8000-000000000002",
        "run_a": "99000000-0000-4000-8000-000000000001",
        "run_b": "99000000-0000-4000-8000-000000000002",
        "run_lease_a": "9a000000-0000-4000-8000-000000000001",
        "run_lease_b": "9a000000-0000-4000-8000-000000000002",
        "capability_a": "9b000000-0000-4000-8000-000000000001",
        "capability_b": "9b000000-0000-4000-8000-000000000002",
        "runner_certificate_a": "9c000000-0000-4000-8000-000000000001",
        "runner_certificate_b": "9c000000-0000-4000-8000-000000000002",
        "group_a": "91000000-0000-4000-8000-000000000001",
        "group_b": "91000000-0000-4000-8000-000000000002",
        "custom_role_a": "92000000-0000-4000-8000-000000000001",
        "custom_role_b": "92000000-0000-4000-8000-000000000002",
        "group_role_assignment_a": "93000000-0000-4000-8000-000000000001",
        "group_role_assignment_b": "93000000-0000-4000-8000-000000000002",
        "enterprise_preflight_a": "94000000-0000-4000-8000-000000000001",
        "enterprise_preflight_b": "94000000-0000-4000-8000-000000000002",
        "scim_directory_a": "bc100000-0000-4000-8000-000000000001",
        "scim_directory_b": "bc100000-0000-4000-8000-000000000002",
        "scim_user_a": "bc200000-0000-4000-8000-000000000001",
        "scim_user_b": "bc200000-0000-4000-8000-000000000002",
        "scim_group_a": "bc300000-0000-4000-8000-000000000001",
        "scim_group_b": "bc300000-0000-4000-8000-000000000002",
        "scim_event_a": "bc400000-0000-4000-8000-000000000001",
        "scim_event_b": "bc400000-0000-4000-8000-000000000002",
        "privacy_subject": "bd000000-0000-4000-8000-000000000001",
        "privacy_hold": "bd100000-0000-4000-8000-000000000001",
        "privacy_manifest": "bd200000-0000-4000-8000-000000000001",
        "privacy_tombstone": "bd300000-0000-4000-8000-000000000001",
        "privacy_scim_event": "bd400000-0000-4000-8000-000000000001",
        "privacy_locator_hash": "d" * 64,
        "scim_token_hash_a": "1" * 64,
        "scim_token_hash_b": "2" * 64,
        "scim_successor_token_hash_a": "3" * 64,
        "identity_a": "40000000-0000-4000-8000-000000000001",
        "identity_b": "40000000-0000-4000-8000-000000000002",
        "session_a": "50000000-0000-4000-8000-000000000001",
        "session_b": "50000000-0000-4000-8000-000000000002",
        "platform_operator": "b0000000-0000-4000-8000-000000000001",
        "platform_approver": "b0000000-0000-4000-8000-000000000002",
        "platform_assignment": "b1000000-0000-4000-8000-000000000001",
        "platform_session": "b2000000-0000-4000-8000-000000000001",
        "service_account_a": "70000000-0000-4000-8000-000000000001",
        "service_account_b": "70000000-0000-4000-8000-000000000002",
        "api_credential_a": "80000000-0000-4000-8000-000000000001",
        "api_credential_b": "80000000-0000-4000-8000-000000000002",
        "billing_subscription_a": "a0000000-0000-4000-8000-000000000001",
        "billing_subscription_b": "a0000000-0000-4000-8000-000000000002",
        "pricing_snapshot_a": "a1000000-0000-4000-8000-000000000001",
        "pricing_snapshot_b": "a1000000-0000-4000-8000-000000000002",
        "billing_entitlement_a": "a2000000-0000-4000-8000-000000000001",
        "billing_entitlement_b": "a2000000-0000-4000-8000-000000000002",
        "usage_event_a": "a3000000-0000-4000-8000-000000000001",
        "usage_event_b": "a3000000-0000-4000-8000-000000000002",
        "billing_reservation_a": "a4000000-0000-4000-8000-000000000001",
        "billing_reservation_b": "a4000000-0000-4000-8000-000000000002",
        "customer_credit_a": "a5000000-0000-4000-8000-000000000001",
        "customer_credit_b": "a5000000-0000-4000-8000-000000000002",
        "customer_reserve_a": "a5000000-0000-4000-8000-000000000003",
        "customer_reserve_b": "a5000000-0000-4000-8000-000000000004",
        "provider_cost_a": "a6000000-0000-4000-8000-000000000001",
        "provider_cost_b": "a6000000-0000-4000-8000-000000000002",
        "billing_reconciliation_a": "a7000000-0000-4000-8000-000000000001",
        "billing_reconciliation_b": "a7000000-0000-4000-8000-000000000002",
        "billing_mismatch_a": "a8000000-0000-4000-8000-000000000001",
        "billing_mismatch_b": "a8000000-0000-4000-8000-000000000002",
        "billing_period_close_a": "aa000000-0000-4000-8000-000000000001",
        "billing_period_close_b": "aa000000-0000-4000-8000-000000000002",
        "billing_metering_receipt_a": "a9000000-0000-4000-8000-000000000001",
        "billing_metering_receipt_b": "a9000000-0000-4000-8000-000000000002",
        "outbox_seed": "60000000-0000-4000-8000-000000000001",
        "outbox_replay": "60000000-0000-4000-8000-000000000002",
        "workspace_a": 11001,
        "workspace_b": 22002,
    }
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "INSERT INTO users (workspace_id, id, is_admin) VALUES "
                    "(:workspace_a, 'runtime-a', false), (:workspace_b, 'runtime-b', false)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_global_users "
                    "(id, status, security_version, display_name, primary_email_normalized) "
                    "VALUES (:actor_a, 'active', 1, 'Recovery A', 'a@example.test'), "
                    "(:actor_b, 'active', 1, 'Recovery B', 'b@example.test'), "
                    "(:approver_a, 'active', 1, 'Approver A', 'approver-a@example.test'), "
                    "(:approver_b, 'active', 1, 'Approver B', 'approver-b@example.test'), "
                    "(:privacy_subject, 'deleted', 2, NULL, NULL)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_staff_principals "
                    "(id, identity_connection_ref, issuer, subject, display_name, "
                    "email_normalized, status, security_version) VALUES "
                    "(:platform_operator, 'recovery-staff-operator', "
                    "'https://staff-idp.recovery.test', 'operator', 'Recovery Operator', "
                    "'operator@staff.recovery.test', 'active', 1), "
                    "(:platform_approver, 'recovery-staff-approver', "
                    "'https://staff-idp.recovery.test', 'approver', 'Recovery Approver', "
                    "'approver@staff.recovery.test', 'active', 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_role_assignments "
                    "(id, principal_id, role, status, version, assigned_by_principal_id, "
                    "approval_ref, reason) VALUES "
                    "(:platform_assignment, :platform_operator, 'platform_operator', "
                    "'active', 1, :platform_approver, 'recovery-two-person-approval', "
                    "'logical restore contract')"
                ),
                identifiers,
            )
            privacy_surfaces = {
                name: {
                    "disposition": disposition,
                    "status": status,
                    "evidence_sha256": hashlib.sha256(name.encode()).hexdigest(),
                }
                for name, disposition, status in (
                    ("control_plane_database", "erase", "erased"),
                    ("runtime_database", "erase", "erased"),
                    ("object_and_artifact_store", "erase", "erased"),
                    ("vector_and_search_indexes", "erase", "erased"),
                    ("caches", "erase", "erased"),
                    ("queues_and_dlq", "erase", "erased"),
                    ("provider_and_connector_state", "erase", "erased"),
                    ("enterprise_identity_provisioning_state", "erase", "erased"),
                    (
                        "enterprise_identity_event_receipts",
                        "anonymize_and_retain",
                        "retained",
                    ),
                    ("runner_worktree_and_recovery_material", "erase", "erased"),
                    ("webhook_state", "erase", "erased"),
                    ("secret_and_kms_references", "cryptographic_erase", "erased"),
                    ("logs_and_traces", "redact_and_retain", "retained"),
                    ("immutable_audit_and_ledger", "anonymize_and_retain", "retained"),
                    ("backups_and_snapshots", "tombstone_then_expire", "pending_retention"),
                )
            }
            connection.execute(
                sa.text(
                    "INSERT INTO saas_privacy_legal_holds "
                    "(id, target_type, target_id, tenant_id, status, scope, authority_ref, "
                    "reason, review_due_at, placed_by_principal_id, "
                    "released_by_principal_id, release_reason, "
                    "version, created_at, updated_at, released_at) VALUES "
                    "(:privacy_hold, 'global_user', :privacy_subject, NULL, 'released', "
                    "CAST(:hold_scope AS jsonb), 'recovery-privacy-case', "
                    "'restore Legal Hold fixture', :privacy_review_due_at, "
                    ":platform_operator, :platform_approver, "
                    "'preservation authority released', 2, :privacy_started_at, "
                    ":privacy_completed_at, :privacy_completed_at)"
                ),
                {
                    **identifiers,
                    "hold_scope": json.dumps(["identity", "audit"]),
                    "privacy_started_at": datetime(2026, 8, 1, 0, 0, tzinfo=UTC),
                    "privacy_review_due_at": datetime(2026, 9, 1, 0, 0, tzinfo=UTC),
                    "privacy_completed_at": datetime(2026, 8, 2, 0, 0, tzinfo=UTC),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_privacy_deletion_manifests "
                    "(id, target_type, target_id, tenant_id, requested_by_principal_id, "
                    "idempotency_key, request_hash, approval_ref, "
                    "completion_approval_ref, reason, "
                    "expected_target_version, preview_hash, status, blockers, surface_outcomes, "
                    "manifest_hash, version, started_at, completed_at, updated_at) VALUES "
                    "(:privacy_manifest, 'global_user', :privacy_subject, NULL, "
                    ":platform_operator, 'recovery-privacy-delete', :request_hash, "
                    "'recovery-privacy-approval', 'recovery-privacy-final-approval', "
                    "'verified erasure request', 1, :preview_hash, "
                    "'completed', CAST(:blockers AS jsonb), CAST(:surfaces AS jsonb), "
                    ":manifest_hash, 17, :privacy_started_at, :privacy_completed_at, "
                    ":privacy_completed_at)"
                ),
                {
                    **identifiers,
                    "request_hash": "a" * 64,
                    "preview_hash": "b" * 64,
                    "blockers": json.dumps([]),
                    "surfaces": json.dumps(privacy_surfaces, sort_keys=True),
                    "manifest_hash": "e" * 64,
                    "privacy_started_at": datetime(2026, 8, 1, 1, 0, tzinfo=UTC),
                    "privacy_completed_at": datetime(2026, 8, 2, 1, 0, tzinfo=UTC),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_privacy_identity_tombstones "
                    "(id, manifest_id, target_user_id, tenant_id, locator_kind, locator_hash, "
                    "created_at) VALUES (:privacy_tombstone, :privacy_manifest, "
                    ":privacy_subject, NULL, 'oidc_subject', :privacy_locator_hash, "
                    ":privacy_completed_at)"
                ),
                {
                    **identifiers,
                    "privacy_completed_at": datetime(2026, 8, 2, 1, 0, tzinfo=UTC),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_auth_sessions "
                    "(id, principal_id, token_hash, csrf_token_hash, security_version, audience, "
                    "origin, authn_method, mfa_strength, authenticated_at, expires_at) VALUES "
                    "(:platform_session, :platform_operator, :platform_token_hash, "
                    ":platform_csrf_hash, 1, 'omnigent-platform-admin', "
                    "'https://platform-admin.recovery.test', 'passkey', "
                    "'phishing_resistant', now(), now() + interval '1 hour')"
                ),
                {
                    **identifiers,
                    "platform_token_hash": "5" * 64,
                    "platform_csrf_hash": "6" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenants (id, slug, name, status, plan, home_region) "
                    "VALUES (:tenant_a, 'recovery-a', 'Recovery A', 'active', "
                    "'test', 'region-a'), "
                    "(:tenant_b, 'recovery-b', 'Recovery B', 'active', 'test', 'region-a')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_tenant_projections "
                    "(tenant_id, slug, name, status, plan, home_region, member_count, "
                    "space_count, source_version, updated_at) VALUES "
                    "(:tenant_a, 'recovery-a', 'Recovery A', 'active', 'test', "
                    "'region-a', 2, 1, 1, now()), "
                    "(:tenant_b, 'recovery-b', 'Recovery B', 'active', 'test', "
                    "'region-a', 2, 1, 1, now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_platform_user_projections "
                    "(user_id, status, display_name, email_masked, membership_count, "
                    "security_version, source_version, created_at, updated_at) VALUES "
                    "(:actor_a, 'active', 'Recovery A', 'a***@example.test', 1, 1, 1, "
                    "now(), now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_spaces (id, tenant_id, slug, name, status) VALUES "
                    "(:space_a, :tenant_a, 'main', 'Main A', 'active'), "
                    "(:space_b, :tenant_b, 'main', 'Main B', 'active')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runtime_placements "
                    "(id, runtime_type, data_region, failure_domain, database_cluster_ref, "
                    "object_store_ref, kms_key_ref, official_schema_revision, capacity_class, "
                    "status) VALUES (:runtime_placement, 'omnigent', 'region-a', 'region-a-1', "
                    "'recovery-db', 'recovery-objects', 'recovery-kms', 'runtime-schema-v1', "
                    "'shared-medium', 'active')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tenant_memberships "
                    "(tenant_id, user_id, role, status, version, joined_at) VALUES "
                    "(:tenant_a, :actor_a, 'owner', 'active', 1, now()), "
                    "(:tenant_b, :actor_b, 'owner', 'active', 1, now()), "
                    "(:tenant_a, :approver_a, 'admin', 'active', 1, now()), "
                    "(:tenant_b, :approver_b, 'admin', 'active', 1, now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_space_memberships "
                    "(tenant_id, space_id, user_id, role, status, version, joined_at) VALUES "
                    "(:tenant_a, :space_a, :actor_a, 'owner', 'active', 1, now()), "
                    "(:tenant_b, :space_b, :actor_b, 'owner', 'active', 1, now()), "
                    "(:tenant_a, :space_a, :approver_a, 'member', 'active', 1, now()), "
                    "(:tenant_b, :space_b, :approver_b, 'member', 'active', 1, now())"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_projects "
                    "(id, tenant_id, space_id, name, visibility, created_by, status, "
                    "authorization_version) VALUES "
                    "(:project_a, :tenant_a, :space_a, 'Recovery Project A', 'private', "
                    ":actor_a, 'active', 1), "
                    "(:project_b, :tenant_b, :space_b, 'Recovery Project B', 'private', "
                    ":actor_b, 'active', 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_tasks "
                    "(id, tenant_id, space_id, project_id, created_by, title, version) VALUES "
                    "(:task_a, :tenant_a, :space_a, :project_a, :actor_a, "
                    "'Recovery metered task A', 1), "
                    "(:task_b, :tenant_b, :space_b, :project_b, :actor_b, "
                    "'Recovery metered task B', 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runs "
                    "(id, tenant_id, space_id, project_id, task_id, created_by, status, version, "
                    "event_sequence, queue_class, priority, idempotency_key, request_hash, input, "
                    "product_revision, upstream_revision, schema_revision, "
                    "adapter_contract_version, lease_owner, lease_token, fence_token, "
                    "lease_expires_at, heartbeat_at) VALUES "
                    "(:run_a, :tenant_a, :space_a, :project_a, :task_a, :actor_a, 'running', 1, "
                    "0, 'interactive', 0, 'recovery-run-a', :run_hash_a, "
                    "CAST(:run_input AS jsonb), "
                    "'recovery-product', 'recovery-upstream', 'pc5c00000002', '0.2.0', "
                    ":runner_a, :run_lease_a, 1, now() + interval '1 hour', now()), "
                    "(:run_b, :tenant_b, :space_b, :project_b, :task_b, :actor_b, 'running', 1, "
                    "0, 'interactive', 0, 'recovery-run-b', :run_hash_b, "
                    "CAST(:run_input AS jsonb), "
                    "'recovery-product', 'recovery-upstream', 'pc5c00000002', '0.2.0', "
                    ":runner_b, :run_lease_b, 1, now() + interval '1 hour', now())"
                ),
                {
                    **identifiers,
                    "run_hash_a": "5" * 64,
                    "run_hash_b": "6" * 64,
                    "run_input": json.dumps({"recovery": "content-blind"}),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_pools "
                    "(id, placement_id, failure_domain, name, queue_class, capacity_slots, "
                    "reserved_slots, status, protocol_version, source_revision, schema_revision, "
                    "adapter_contract_version) VALUES (:runner_pool, :runtime_placement, "
                    "'region-a-1', 'recovery-metering', 'interactive', 4, 0, 'active', 2, "
                    "'recovery-upstream', 'runtime-schema-v1', '0.2.0')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_registrations "
                    "(id, pool_id, placement_id, instance_key, failure_domain, status, "
                    "connection_generation, connection_token_hash, protocol_version, "
                    "source_revision, schema_revision, adapter_contract_version, capabilities, "
                    "capabilities_hash, max_concurrency, active_leases, last_heartbeat_at, "
                    "registered_at) VALUES "
                    "(:runner_a, :runner_pool, :runtime_placement, 'recovery-runner-a', "
                    "'region-a-1', 'online', 1, :runner_token_a, 2, 'recovery-upstream', "
                    "'runtime-schema-v1', '0.2.0', CAST(:capabilities AS jsonb), :cap_hash, "
                    "2, 1, now(), now()), "
                    "(:runner_b, :runner_pool, :runtime_placement, 'recovery-runner-b', "
                    "'region-a-1', 'online', 1, :runner_token_b, 2, 'recovery-upstream', "
                    "'runtime-schema-v1', '0.2.0', CAST(:capabilities AS jsonb), :cap_hash, "
                    "2, 1, now(), now())"
                ),
                {
                    **identifiers,
                    "runner_token_a": "7" * 64,
                    "runner_token_b": "8" * 64,
                    "capabilities": json.dumps(["shell"]),
                    "cap_hash": "9" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_run_dispatches "
                    "(run_id, tenant_id, space_id, project_id, pool_id, queue_class, "
                    "required_capabilities, requirements_hash, cost_units, eligible_at, "
                    "max_wait_at, status, selected_runner_id, selected_failure_domain, "
                    "dispatch_generation) VALUES "
                    "(:run_a, :tenant_a, :space_a, :project_a, :runner_pool, 'interactive', "
                    "CAST(:capabilities AS jsonb), :requirements_hash, 1, now() - interval "
                    "'1 minute', now() + interval '1 hour', 'leased', :runner_a, "
                    "'region-a-1', 1), "
                    "(:run_b, :tenant_b, :space_b, :project_b, :runner_pool, 'interactive', "
                    "CAST(:capabilities AS jsonb), :requirements_hash, 1, now() - interval "
                    "'1 minute', now() + interval '1 hour', 'leased', :runner_b, "
                    "'region-a-1', 1)"
                ),
                {
                    **identifiers,
                    "capabilities": json.dumps(["shell"]),
                    "requirements_hash": "a" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_capability_tokens "
                    "(id, token_hash, tenant_id, space_id, project_id, run_id, runner_id, "
                    "runner_connection_generation, dispatch_generation, fence_token, "
                    "allowed_actions, resource_scope, issued_at, expires_at) VALUES "
                    "(:capability_a, :capability_hash_a, :tenant_a, :space_a, :project_a, "
                    ":run_a, :runner_a, 1, 1, 1, CAST(:actions AS jsonb), "
                    "CAST(:scope_a AS jsonb), now() - interval '1 minute', "
                    "now() + interval '1 hour'), "
                    "(:capability_b, :capability_hash_b, :tenant_b, :space_b, :project_b, "
                    ":run_b, :runner_b, 1, 1, 1, CAST(:actions AS jsonb), "
                    "CAST(:scope_b AS jsonb), now() - interval '1 minute', "
                    "now() + interval '1 hour')"
                ),
                {
                    **identifiers,
                    "capability_hash_a": "b" * 64,
                    "capability_hash_b": "c" * 64,
                    "actions": json.dumps(["billing.usage.record"]),
                    "scope_a": json.dumps(
                        {
                            "tenant_id": identifiers["tenant_a"],
                            "space_id": identifiers["space_a"],
                            "project_id": identifiers["project_a"],
                            "run_id": identifiers["run_a"],
                            "runner_id": identifiers["runner_a"],
                            "billing_meter": "llm.input_tokens",
                        }
                    ),
                    "scope_b": json.dumps(
                        {
                            "tenant_id": identifiers["tenant_b"],
                            "space_id": identifiers["space_b"],
                            "project_id": identifiers["project_b"],
                            "run_id": identifiers["run_b"],
                            "runner_id": identifiers["runner_b"],
                            "billing_meter": "llm.input_tokens",
                        }
                    ),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_runner_certificates "
                    "(id, runner_id, runner_connection_generation, purpose, fingerprint_sha256, "
                    "spki_sha256, serial_hex, spiffe_id, trust_bundle_version, "
                    "rotation_generation, certificate_not_before, certificate_not_after, status, "
                    "activated_at) VALUES "
                    "(:runner_certificate_a, :runner_a, 1, 'billing_metering', "
                    ":certificate_fingerprint_a, :spki_a, 'aa01', :spiffe_a, 'recovery-v1', 1, "
                    "now() - interval '1 minute', now() + interval '1 hour', 'active', now()), "
                    "(:runner_certificate_b, :runner_b, 1, 'billing_metering', "
                    ":certificate_fingerprint_b, :spki_b, 'bb01', :spiffe_b, 'recovery-v1', 1, "
                    "now() - interval '1 minute', now() + interval '1 hour', 'active', now())"
                ),
                {
                    **identifiers,
                    "certificate_fingerprint_a": "d" * 64,
                    "certificate_fingerprint_b": "e" * 64,
                    "spki_a": "f" * 64,
                    "spki_b": "0" * 64,
                    "spiffe_a": f"spiffe://omnigent/runner/{identifiers['runner_a']}",
                    "spiffe_b": f"spiffe://omnigent/runner/{identifiers['runner_b']}",
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_groups "
                    "(id, tenant_id, name, description, status, version, created_by) VALUES "
                    "(:group_a, :tenant_a, 'Recovery Group A', NULL, 'active', 1, :actor_a), "
                    "(:group_b, :tenant_b, 'Recovery Group B', NULL, 'active', 1, :actor_b)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_group_memberships "
                    "(tenant_id, group_id, user_id, status, expires_at, version, created_by) "
                    "VALUES (:tenant_a, :group_a, :actor_a, 'active', NULL, 1, :actor_a), "
                    "(:tenant_b, :group_b, :actor_b, 'active', NULL, 1, :actor_b)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_custom_roles "
                    "(id, tenant_id, space_id, project_id, name, description, permissions, "
                    "status, version, created_by) VALUES "
                    "(:custom_role_a, :tenant_a, :space_a, :project_a, 'Recovery Reader A', "
                    "NULL, CAST(:role_permissions AS jsonb), 'active', 1, :actor_a), "
                    "(:custom_role_b, :tenant_b, :space_b, :project_b, 'Recovery Reader B', "
                    "NULL, CAST(:role_permissions AS jsonb), 'active', 1, :actor_b)"
                ),
                {**identifiers, "role_permissions": json.dumps(["project.read_metadata"])},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_group_role_assignments "
                    "(id, tenant_id, space_id, project_id, group_id, custom_role_id, status, "
                    "expires_at, version, created_by) VALUES "
                    "(:group_role_assignment_a, :tenant_a, :space_a, :project_a, :group_a, "
                    ":custom_role_a, 'active', NULL, 1, :actor_a), "
                    "(:group_role_assignment_b, :tenant_b, :space_b, :project_b, :group_b, "
                    ":custom_role_b, 'active', NULL, 1, :actor_b)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_access_preflights "
                    "(id, tenant_id, space_id, project_id, operation_type, target_id, "
                    "target_version, requested_by, reason, approval_policy, impact_snapshot, "
                    "snapshot_hash, status, approved_by, approval_reason, approved_at, "
                    "executed_at, expires_at) VALUES "
                    "(:enterprise_preflight_a, :tenant_a, NULL, NULL, 'group_archive', "
                    ":group_a, 1, :actor_a, 'recovery group preflight', "
                    "'different_principal', CAST(:group_snapshot AS jsonb), :group_hash, "
                    "'pending_approval', NULL, NULL, NULL, NULL, now() + interval '1 day'), "
                    "(:enterprise_preflight_b, :tenant_b, :space_b, :project_b, "
                    "'custom_role_retire', :custom_role_b, 1, :actor_b, "
                    "'recovery role preflight', 'different_principal', "
                    "CAST(:role_snapshot AS jsonb), :role_hash, 'approved', :approver_b, "
                    "'replacement verified', now(), NULL, now() + interval '1 day')"
                ),
                {
                    **identifiers,
                    "group_snapshot": json.dumps(
                        {"operation_type": "group_archive", "summary": {"members": 1}}
                    ),
                    "role_snapshot": json.dumps(
                        {
                            "operation_type": "custom_role_retire",
                            "summary": {"assignments": 1},
                        }
                    ),
                    "group_hash": "a" * 64,
                    "role_hash": "b" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_scim_directories "
                    "(id, tenant_id, display_name, token_hash, token_prefix, status, version, "
                    "configured_by, successor_token_hash, successor_token_prefix, "
                    "rotation_activates_at, rotation_grace_expires_at) VALUES "
                    "(:scim_directory_a, :tenant_a, 'Recovery SCIM A', :scim_token_hash_a, "
                    "'omniscim_recovery_a', 'active', 2, :actor_a, "
                    ":scim_successor_token_hash_a, 'omniscim_successor_a', "
                    "'2026-08-08T12:00:00+00:00', '2026-08-08T13:00:00+00:00'), "
                    "(:scim_directory_b, :tenant_b, 'Recovery SCIM B', :scim_token_hash_b, "
                    "'omniscim_recovery_b', 'active', 1, :actor_b, NULL, NULL, NULL, NULL)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_scim_users "
                    "(id, tenant_id, directory_id, external_id, user_id, "
                    "user_name_normalized, display_name, active, version, source_version, "
                    "source_state_hash) VALUES "
                    "(:scim_user_a, :tenant_a, :scim_directory_a, 'recovery-user-a', "
                    ":actor_a, 'a@example.test', 'Recovery A', true, 1, 1, :state_hash_a), "
                    "(:scim_user_b, :tenant_b, :scim_directory_b, 'recovery-user-b', "
                    ":actor_b, 'b@example.test', 'Recovery B', true, 1, 1, :state_hash_b)"
                ),
                {**identifiers, "state_hash_a": "3" * 64, "state_hash_b": "4" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_scim_groups "
                    "(id, tenant_id, directory_id, external_id, enterprise_group_id, "
                    "display_name, active, version, source_version, source_state_hash) VALUES "
                    "(:scim_group_a, :tenant_a, :scim_directory_a, 'recovery-group-a', "
                    ":group_a, 'Recovery Group A', true, 1, 1, :state_hash_a), "
                    "(:scim_group_b, :tenant_b, :scim_directory_b, 'recovery-group-b', "
                    ":group_b, 'Recovery Group B', true, 1, 1, :state_hash_b)"
                ),
                {**identifiers, "state_hash_a": "5" * 64, "state_hash_b": "6" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_scim_events "
                    "(id, tenant_id, directory_id, event_id, resource_type, resource_id, "
                    "source_version, request_hash, disposition, result) VALUES "
                    "(:scim_event_a, :tenant_a, :scim_directory_a, 'recovery-event-a', "
                    "'User', :scim_user_a, 1, :request_hash_a, 'applied', "
                    "CAST(:result_a AS jsonb)), "
                    "(:scim_event_b, :tenant_b, :scim_directory_b, 'recovery-event-b', "
                    "'User', :scim_user_b, 1, :request_hash_b, 'applied', "
                    "CAST(:result_b AS jsonb))"
                ),
                {
                    **identifiers,
                    "request_hash_a": "7" * 64,
                    "request_hash_b": "8" * 64,
                    "result_a": json.dumps({"resource_type": "User", "disposition": "applied"}),
                    "result_b": json.dumps({"resource_type": "User", "disposition": "applied"}),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_enterprise_scim_events "
                    "(id, tenant_id, directory_id, event_id, resource_type, resource_id, "
                    "source_version, request_hash, disposition, result, redacted_at, "
                    "redaction_manifest_id, original_result_hash) VALUES "
                    "(:privacy_scim_event, :tenant_a, :scim_directory_a, "
                    "'recovery-privacy-redacted', 'User', :privacy_subject, 1, "
                    ":request_hash, 'applied', CAST(:result AS jsonb), :redacted_at, "
                    ":privacy_manifest, :original_result_hash)"
                ),
                {
                    **identifiers,
                    "request_hash": "9" * 64,
                    "result": json.dumps(
                        {
                            "redacted": True,
                            "manifest_id": identifiers["privacy_manifest"],
                            "resource_type": "User",
                        }
                    ),
                    "redacted_at": datetime(2026, 8, 2, 1, 0, tzinfo=UTC),
                    "original_result_hash": "f" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_identity_connections "
                    "(id, user_id, provider, issuer, subject, email_normalized, "
                    "email_verified, status) VALUES "
                    "(:identity_a, :actor_a, 'oidc', 'https://id.example.test', 'actor-a', "
                    "'a@example.test', true, 'active'), "
                    "(:identity_b, :actor_b, 'oidc', 'https://id.example.test', 'actor-b', "
                    "'b@example.test', true, 'active')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_auth_sessions "
                    "(id, user_id, token_hash, security_version, authn_method, expires_at) VALUES "
                    "(:session_a, :actor_a, :token_a, 1, 'oidc', now() + interval '1 day'), "
                    "(:session_b, :actor_b, :token_b, 1, 'oidc', now() + interval '1 day')"
                ),
                {
                    **identifiers,
                    "token_a": "a" * 64,
                    "token_b": "b" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_service_accounts "
                    "(id, tenant_id, space_id, name, steward_user_id, created_by, status, "
                    "security_version) VALUES "
                    "(:service_account_a, :tenant_a, :space_a, 'Recovery Bot A', :actor_a, "
                    ":actor_a, 'active', 1), "
                    "(:service_account_b, :tenant_b, :space_b, 'Recovery Bot B', :actor_b, "
                    ":actor_b, 'active', 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_api_credentials "
                    "(id, tenant_id, service_account_id, name, token_hash, display_prefix, "
                    "permission_scopes, allowed_networks, account_security_version, status, "
                    "expires_at, created_by) VALUES "
                    "(:api_credential_a, :tenant_a, :service_account_a, 'Recovery Key A', "
                    ":token_hash_a, 'omk_recovery_a', CAST(:scopes AS jsonb), '[]'::jsonb, 1, "
                    "'active', now() + interval '1 day', :actor_a), "
                    "(:api_credential_b, :tenant_b, :service_account_b, 'Recovery Key B', "
                    ":token_hash_b, 'omk_recovery_b', CAST(:scopes AS jsonb), '[]'::jsonb, 1, "
                    "'active', now() + interval '1 day', :actor_b)"
                ),
                {
                    **identifiers,
                    "token_hash_a": "e" * 64,
                    "token_hash_b": "f" * 64,
                    "scopes": json.dumps(["project.read_metadata"]),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_subscriptions "
                    "(id, tenant_id, plan_key, status, current_period_start, "
                    "current_period_end, cancel_at_period_end, version, updated_by) VALUES "
                    "(:billing_subscription_a, :tenant_a, 'recovery-v1', 'active', now(), "
                    "now() + interval '30 days', false, 1, :actor_a), "
                    "(:billing_subscription_b, :tenant_b, 'recovery-v1', 'active', now(), "
                    "now() + interval '30 days', false, 1, :actor_b)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_pricing_snapshots "
                    "(id, tenant_id, plan_key, currency, rates, version, effective_from, "
                    "created_by) VALUES "
                    "(:pricing_snapshot_a, :tenant_a, 'recovery-v1', 'USD', "
                    "CAST(:rates AS jsonb), 1, now(), :actor_a), "
                    "(:pricing_snapshot_b, :tenant_b, 'recovery-v1', 'USD', "
                    "CAST(:rates AS jsonb), 1, now(), :actor_b)"
                ),
                {
                    **identifiers,
                    "rates": json.dumps(
                        {
                            "llm.input_tokens": {
                                "unit": "tokens",
                                "unit_size": "1",
                                "minor_per_unit": 25,
                            }
                        }
                    ),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_entitlements "
                    "(id, tenant_id, subscription_id, scope_type, scope_key, meter, unit, "
                    "limit_quantity, reserved_quantity, consumed_quantity, concurrency_limit, "
                    "active_reservations, hard_limit, period, period_start, period_end, status, "
                    "version, updated_by) VALUES "
                    "(:billing_entitlement_a, :tenant_a, :billing_subscription_a, 'tenant', "
                    ":scope_key_a, 'llm.input_tokens', 'tokens', 100, 1, 0, 2, 1, "
                    "true, 'month', now(), now() + interval '30 days', 'active', 1, :actor_a), "
                    "(:billing_entitlement_b, :tenant_b, :billing_subscription_b, 'tenant', "
                    ":scope_key_b, 'llm.input_tokens', 'tokens', 100, 1, 0, 2, 1, "
                    "true, 'month', now(), now() + interval '30 days', 'active', 1, :actor_b)"
                ),
                {
                    **identifiers,
                    "scope_key_a": str(identifiers["tenant_a"]),
                    "scope_key_b": str(identifiers["tenant_b"]),
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_usage_events "
                    "(id, tenant_id, space_id, project_id, run_id, user_id, meter, quantity, "
                    "unit, provider, provider_request_id, idempotency_key, pricing_snapshot_id, "
                    "currency, customer_charge_minor, attributes, occurred_at) VALUES "
                    "(:usage_event_a, :tenant_a, :space_a, :project_a, :run_a, :actor_a, "
                    "'llm.input_tokens', 1, 'tokens', 'recovery', 'recovery-request-a', "
                    "'recovery-usage-a', :pricing_snapshot_a, 'USD', 25, "
                    "CAST(:attributes AS jsonb), now()), "
                    "(:usage_event_b, :tenant_b, :space_b, :project_b, :run_b, :actor_b, "
                    "'llm.input_tokens', 1, 'tokens', 'recovery', 'recovery-request-b', "
                    "'recovery-usage-b', :pricing_snapshot_b, 'USD', 25, "
                    "CAST(:attributes AS jsonb), now())"
                ),
                {**identifiers, "attributes": json.dumps({"model": "recovery-model"})},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_metering_receipts "
                    "(id, tenant_id, space_id, project_id, run_id, usage_event_id, runner_id, "
                    "runner_connection_generation, runner_certificate_id, "
                    "certificate_fingerprint_sha256, capability_id, dispatch_generation, "
                    "fence_token, idempotency_key, request_hash) VALUES "
                    "(:billing_metering_receipt_a, :tenant_a, :space_a, :project_a, :run_a, "
                    ":usage_event_a, :runner_a, 1, :runner_certificate_a, "
                    ":certificate_fingerprint_a, :capability_a, 1, 1, 'recovery-metering-a', "
                    ":metering_hash_a), "
                    "(:billing_metering_receipt_b, :tenant_b, :space_b, :project_b, :run_b, "
                    ":usage_event_b, :runner_b, 1, :runner_certificate_b, "
                    ":certificate_fingerprint_b, :capability_b, 1, 1, 'recovery-metering-b', "
                    ":metering_hash_b)"
                ),
                {
                    **identifiers,
                    "certificate_fingerprint_a": "d" * 64,
                    "certificate_fingerprint_b": "e" * 64,
                    "metering_hash_a": "1" * 64,
                    "metering_hash_b": "2" * 64,
                },
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_balances "
                    "(tenant_id, currency, available_minor, reserved_minor, consumed_minor, "
                    "version) VALUES (:tenant_a, 'USD', 90, 10, 0, 1), "
                    "(:tenant_b, 'USD', 90, 10, 0, 1)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_reservations "
                    "(id, tenant_id, entitlement_id, operation_key, meter, unit, "
                    "reserved_quantity, settled_quantity, reserved_minor, settled_minor, "
                    "released_minor, refunded_minor, currency, status, version, created_by) "
                    "VALUES (:billing_reservation_a, :tenant_a, :billing_entitlement_a, "
                    "'recovery-run-a', 'llm.input_tokens', 'tokens', 1, 0, 10, 0, 0, 0, "
                    "'USD', 'reserved', 1, :actor_a), "
                    "(:billing_reservation_b, :tenant_b, :billing_entitlement_b, "
                    "'recovery-run-b', 'llm.input_tokens', 'tokens', 1, 0, 10, 0, 0, 0, "
                    "'USD', 'reserved', 1, :actor_b)"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_customer_ledger_entries "
                    "(id, tenant_id, reservation_id, operation_type, amount_minor, "
                    "delta_available_minor, delta_reserved_minor, delta_consumed_minor, "
                    "currency, idempotency_key, request_hash, created_by, occurred_at) VALUES "
                    "(:customer_credit_a, :tenant_a, NULL, 'credit', 100, 100, 0, 0, 'USD', "
                    "'recovery-credit-a', :credit_hash, :actor_a, now()), "
                    "(:customer_reserve_a, :tenant_a, :billing_reservation_a, 'reserve', 10, "
                    "-10, 10, 0, 'USD', 'recovery-reserve-a', :reserve_hash, :actor_a, now()), "
                    "(:customer_credit_b, :tenant_b, NULL, 'credit', 100, 100, 0, 0, 'USD', "
                    "'recovery-credit-b', :credit_hash, :actor_b, now()), "
                    "(:customer_reserve_b, :tenant_b, :billing_reservation_b, 'reserve', 10, "
                    "-10, 10, 0, 'USD', 'recovery-reserve-b', :reserve_hash, :actor_b, now())"
                ),
                {**identifiers, "credit_hash": "1" * 64, "reserve_hash": "2" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_provider_cost_entries "
                    "(id, tenant_id, usage_event_id, provider, provider_receipt_id, kind, "
                    "amount_minor, currency, idempotency_key, request_hash, recorded_by, "
                    "occurred_at) VALUES "
                    "(:provider_cost_a, :tenant_a, :usage_event_a, 'recovery', "
                    "'recovery-receipt-a', 'final', 5, 'USD', 'recovery-cost-a', :cost_hash, "
                    ":actor_a, now()), "
                    "(:provider_cost_b, :tenant_b, :usage_event_b, 'recovery', "
                    "'recovery-receipt-b', 'final', 5, 'USD', 'recovery-cost-b', :cost_hash, "
                    ":actor_b, now())"
                ),
                {**identifiers, "cost_hash": "3" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_reconciliation_batches "
                    "(id, tenant_id, period_start, period_end, status, usage_event_count, "
                    "customer_settlement_count, provider_cost_count, customer_charge_minor, "
                    "customer_settled_minor, provider_cost_minor, mismatch_count, "
                    "evidence_sha256, created_by) VALUES "
                    "(:billing_reconciliation_a, :tenant_a, now() - interval '1 day', now(), "
                    "'exception', 1, 0, 1, 25, 0, 5, 1, :evidence_hash, :actor_a), "
                    "(:billing_reconciliation_b, :tenant_b, now() - interval '1 day', now(), "
                    "'exception', 1, 0, 1, 25, 0, 5, 1, :evidence_hash, :actor_b)"
                ),
                {**identifiers, "evidence_hash": "4" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_reconciliation_mismatches "
                    "(id, tenant_id, batch_id, usage_event_id, mismatch_type, expected_minor, "
                    "actual_minor, currency, status) VALUES "
                    "(:billing_mismatch_a, :tenant_a, :billing_reconciliation_a, "
                    ":usage_event_a, 'missing_customer_settlement', 25, NULL, 'USD', 'open'), "
                    "(:billing_mismatch_b, :tenant_b, :billing_reconciliation_b, "
                    ":usage_event_b, 'missing_customer_settlement', 25, NULL, 'USD', 'open')"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_billing_reconciliation_mismatches "
                    "SET status = 'resolved', resolution = 'source close verified', "
                    "resolved_by = :actor_a, resolved_at = now() "
                    "WHERE id = :billing_mismatch_a"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_period_closes "
                    "(id, tenant_id, reconciliation_batch_id, period_start, period_end, "
                    "status, rolled_entitlement_count, usage_event_count, "
                    "customer_charge_minor, customer_settled_minor, provider_cost_minor, "
                    "reconciliation_evidence_sha256, close_evidence_sha256, closed_by, "
                    "closed_at) SELECT :billing_period_close_a, batch.tenant_id, batch.id, "
                    "batch.period_start, batch.period_end, 'closed_with_resolved_exceptions', "
                    "0, batch.usage_event_count, batch.customer_charge_minor, "
                    "batch.customer_settled_minor, batch.provider_cost_minor, "
                    "batch.evidence_sha256, :close_hash, :actor_a, now() "
                    "FROM saas_billing_reconciliation_batches batch "
                    "WHERE batch.id = :billing_reconciliation_a"
                ),
                {**identifiers, "close_hash": "5" * 64},
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at) VALUES "
                    "(:outbox_seed, :tenant_a, 'recovery', 'seed', 'recovery.seeded', "
                    "CAST(:payload AS jsonb), 'recovery-seed', :request_hash, 0, now())"
                ),
                {
                    **identifiers,
                    "payload": json.dumps({"kind": "ci_contract", "tenant": "a"}),
                    "request_hash": "c" * 64,
                },
            )
    finally:
        engine.dispose()
    return identifiers


def _apply_post_backup_replay(
    endpoint: PostgreSqlEndpoint,
    database: str,
    identifiers: Mapping[str, str | int],
) -> None:
    replay_parameters = {
        **identifiers,
        "replay_at": datetime(2026, 8, 5, 0, 0, tzinfo=UTC),
        "tenant_b_key": str(identifiers["tenant_b"]),
    }
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            connection.execute(
                sa.text("UPDATE saas_global_users SET security_version = 2 WHERE id = :actor_b"),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_identity_connections SET status = 'revoked' "
                    "WHERE id = :identity_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_auth_sessions SET revoked_at = :replay_at WHERE id = :session_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_service_accounts SET status = 'suspended', "
                    "security_version = 2, updated_at = :replay_at "
                    "WHERE id = :service_account_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_api_credentials SET status = 'revoked', "
                    "revoked_at = :replay_at WHERE id = :api_credential_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_billing_subscriptions SET status = 'suspended', version = 2, "
                    "updated_at = :replay_at WHERE id = :billing_subscription_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_billing_reconciliation_mismatches "
                    "SET status = 'resolved', resolution = 'recovery replay verified', "
                    "resolved_by = :actor_b, resolved_at = :replay_at "
                    "WHERE id = :billing_mismatch_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_billing_period_closes "
                    "(id, tenant_id, reconciliation_batch_id, period_start, period_end, "
                    "status, rolled_entitlement_count, usage_event_count, "
                    "customer_charge_minor, customer_settled_minor, provider_cost_minor, "
                    "reconciliation_evidence_sha256, close_evidence_sha256, closed_by, "
                    "closed_at) SELECT :billing_period_close_b, batch.tenant_id, batch.id, "
                    "batch.period_start, batch.period_end, 'closed_with_resolved_exceptions', "
                    "0, batch.usage_event_count, batch.customer_charge_minor, "
                    "batch.customer_settled_minor, batch.provider_cost_minor, "
                    "batch.evidence_sha256, :close_hash, :actor_b, :replay_at "
                    "FROM saas_billing_reconciliation_batches batch "
                    "WHERE batch.id = :billing_reconciliation_b"
                ),
                {**replay_parameters, "close_hash": "6" * 64},
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_tenant_memberships SET status = 'removed', version = 2 "
                    "WHERE tenant_id = :tenant_b AND user_id = :actor_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_space_memberships SET status = 'removed', version = 2 "
                    "WHERE tenant_id = :tenant_b AND space_id = :space_b "
                    "AND user_id = :actor_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_group_memberships "
                    "SET status = 'removed', version = 2 "
                    "WHERE tenant_id = :tenant_b AND group_id = :group_b AND user_id = :actor_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_group_role_assignments "
                    "SET status = 'revoked', version = 2 "
                    "WHERE id = :group_role_assignment_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_groups SET status = 'archived', version = 2, "
                    "archived_at = :replay_at, archived_by = :actor_b, "
                    "archive_reason = 'recovery replay group archive' "
                    "WHERE id = :group_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_custom_roles SET status = 'retired', version = 2, "
                    "retired_at = :replay_at, retired_by = :actor_b, "
                    "retire_reason = 'recovery replay role retirement' "
                    "WHERE id = :custom_role_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_enterprise_access_preflights "
                    "SET status = 'executed', executed_at = :replay_at "
                    "WHERE id = :enterprise_preflight_b"
                ),
                replay_parameters,
            )
            connection.execute(
                sa.text(
                    "UPDATE saas_tenants SET status = 'pending_deletion' WHERE id = :tenant_b"
                ),
                identifiers,
            )
            connection.execute(
                sa.text(
                    "INSERT INTO saas_control_plane_outbox "
                    "(id, tenant_id, aggregate_type, aggregate_key, event_type, payload, "
                    "idempotency_key, request_hash, attempt_count, available_at, created_at) "
                    "VALUES (:outbox_replay, :tenant_b, 'tenant', :tenant_b_key, "
                    "'tenant.deletion_requested', CAST(:payload AS jsonb), "
                    "'recovery-replay', :request_hash, 0, :replay_at, :replay_at)"
                ),
                {
                    **replay_parameters,
                    "payload": json.dumps(
                        {
                            "identity_revoked": True,
                            "service_account_suspended": True,
                            "api_credential_revoked": True,
                            "membership_removed": True,
                            "tenant_pending_deletion": True,
                        }
                    ),
                    "request_hash": "d" * 64,
                },
            )
    finally:
        engine.dispose()


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _database_digest(endpoint: PostgreSqlEndpoint, database: str) -> tuple[str, dict[str, int]]:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    table_counts: dict[str, int] = {}
    canonical_rows: dict[str, list[dict[str, Any]]] = {}
    try:
        with engine.connect() as connection:
            inspector = sa.inspect(connection)
            for table in _SELECTED_HASH_TABLES:
                if not inspector.has_table(table, schema="public"):
                    raise PostgreSqlRestoreContractError(f"missing hash table {table}")
                quoted = connection.dialect.identifier_preparer.quote(table)
                rows = [
                    {str(key): _normalize(value) for key, value in row.items()}
                    for row in connection.execute(
                        sa.text(f"SELECT * FROM public.{quoted}")
                    ).mappings()
                ]
                rows.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
                canonical_rows[table] = rows
                table_counts[table] = len(rows)
    finally:
        engine.dispose()
    encoded = json.dumps(
        canonical_rows,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), table_counts


def _verify_control_plane_rls(connection: sa.Connection) -> None:
    rows = connection.execute(
        sa.text(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relname = ANY(:tables)"
        ),
        {"tables": sorted(CONTROL_PLANE_RLS_TABLES)},
    ).mappings()
    facts = {row["relname"]: (row["relrowsecurity"], row["relforcerowsecurity"]) for row in rows}
    if set(facts) != set(CONTROL_PLANE_RLS_TABLES) or any(
        fact != (True, True) for fact in facts.values()
    ):
        raise PostgreSqlRestoreContractError("restored control-plane forced RLS drifted")


def _verify_restored_database(
    endpoint: PostgreSqlEndpoint,
    database: str,
    identifiers: Mapping[str, str | int],
    *,
    expected_saas_head: str,
) -> dict[str, Any]:
    engine = sa.create_engine(endpoint.sqlalchemy_url(database), poolclass=sa.pool.NullPool)
    try:
        with engine.begin() as connection:
            saas_head = connection.execute(
                sa.text("SELECT version_num FROM saas_alembic_version")
            ).scalar_one()
            if saas_head != expected_saas_head:
                raise PostgreSqlRestoreContractError("restored SaaS migration head drifted")
            official_heads = sorted(
                connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalars()
            )
            if not official_heads:
                raise PostgreSqlRestoreContractError("restored official migration head is missing")
            _verify_control_plane_rls(connection)
            verify_runtime_rls(connection)
            platform_counts = connection.execute(
                sa.text(
                    "SELECT "
                    "(SELECT count(*) FROM saas_platform_staff_principals), "
                    "(SELECT count(*) FROM saas_platform_role_assignments), "
                    "(SELECT count(*) FROM saas_platform_auth_sessions), "
                    "(SELECT count(*) FROM saas_platform_tenant_projections), "
                    "(SELECT count(*) FROM saas_platform_user_projections)"
                )
            ).one()
            if tuple(platform_counts) != (2, 1, 1, 2, 1):
                raise PostgreSqlRestoreContractError(
                    "restored Staff Realm or content-blind platform projections drifted"
                )
            privacy_facts = connection.execute(
                sa.text(
                    "SELECT subject.status, subject.display_name IS NULL, "
                    "subject.primary_email_normalized IS NULL, hold.status, hold.version, "
                    "hold.review_due_at > hold.created_at, "
                    "manifest.status, manifest.version, manifest.manifest_hash, "
                    "manifest.completion_approval_ref, "
                    "(SELECT count(*) FROM json_object_keys(manifest.surface_outcomes)), "
                    "tombstone.locator_hash, "
                    "receipt.result->>'redacted', receipt.redaction_manifest_id::text, "
                    "receipt.original_result_hash "
                    "FROM saas_global_users subject "
                    "JOIN saas_privacy_legal_holds hold ON hold.target_id = subject.id "
                    "JOIN saas_privacy_deletion_manifests manifest "
                    "ON manifest.target_id = subject.id "
                    "JOIN saas_privacy_identity_tombstones tombstone "
                    "ON tombstone.manifest_id = manifest.id "
                    "JOIN saas_enterprise_scim_events receipt "
                    "ON receipt.redaction_manifest_id = manifest.id "
                    "WHERE subject.id = :privacy_subject"
                ),
                identifiers,
            ).one()
            if tuple(privacy_facts) != (
                "deleted",
                True,
                True,
                "released",
                2,
                True,
                "completed",
                17,
                "e" * 64,
                "recovery-privacy-final-approval",
                15,
                identifiers["privacy_locator_hash"],
                "true",
                identifiers["privacy_manifest"],
                "f" * 64,
            ):
                raise PostgreSqlRestoreContractError(
                    "restored Legal Hold, deletion Manifest, Tombstone, "
                    "or redacted receipt drifted"
                )
            privacy_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, "
                    "pg_has_role('saas_privacy_executor', "
                    "'saas_platform_governance', 'member'), "
                    "has_table_privilege('saas_platform_governance', "
                    "'saas_global_users', 'SELECT'), "
                    "has_table_privilege('saas_privacy_executor', "
                    "'saas_global_users', 'SELECT') "
                    "FROM pg_roles WHERE rolname = 'saas_privacy_executor'"
                )
            ).one()
            if tuple(privacy_role) != (False, False, False, True, False, True):
                raise PostgreSqlRestoreContractError(
                    "restored privacy executor authority is missing or Staff PII grants widened"
                )
            dispatcher_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, "
                    "pg_has_role('saas_privacy_dispatcher', "
                    "'saas_platform_governance', 'member'), "
                    "pg_has_role('saas_privacy_dispatcher', "
                    "'saas_privacy_executor', 'member'), "
                    "has_table_privilege('saas_privacy_dispatcher', "
                    "'saas_global_users', 'SELECT'), "
                    "has_column_privilege('saas_privacy_dispatcher', "
                    "'saas_privacy_deletion_work_items', 'status', 'UPDATE'), "
                    "has_table_privilege('saas_privacy_dispatcher', "
                    "'saas_privacy_deletion_attempts', 'INSERT') "
                    "FROM pg_roles WHERE rolname = 'saas_privacy_dispatcher'"
                )
            ).one()
            if tuple(dispatcher_role) != (
                False,
                False,
                False,
                False,
                False,
                False,
                True,
                True,
            ):
                raise PostgreSqlRestoreContractError(
                    "restored privacy dispatcher is missing or gained Staff/PII authority"
                )
            notification_scheduler_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, "
                    "pg_has_role('saas_notification_scheduler', "
                    "'saas_platform_governance', 'member'), "
                    "has_table_privilege('saas_notification_scheduler', "
                    "'saas_approval_work_items', 'SELECT'), "
                    "has_column_privilege('saas_notification_scheduler', "
                    "'saas_approval_work_items', 'status', 'UPDATE'), "
                    "has_column_privilege('saas_notification_scheduler', "
                    "'saas_approval_work_items', 'priority', 'UPDATE'), "
                    "has_column_privilege('saas_notification_scheduler', "
                    "'saas_approval_work_items', 'escalation_at', 'UPDATE'), "
                    "has_column_privilege('saas_notification_scheduler', "
                    "'saas_approval_work_items', 'action', 'UPDATE'), "
                    "has_table_privilege('saas_notification_scheduler', "
                    "'saas_notification_deliveries', 'INSERT'), "
                    "has_table_privilege('saas_notification_scheduler', "
                    "'saas_notification_deliveries', 'DELETE') "
                    "FROM pg_roles WHERE rolname = 'saas_notification_scheduler'"
                )
            ).one()
            if tuple(notification_scheduler_role) != (
                False,
                False,
                False,
                False,
                True,
                True,
                True,
                True,
                False,
                True,
                False,
            ):
                raise PostgreSqlRestoreContractError(
                    "restored notification scheduler authority widened or drifted"
                )
            notification_dispatcher_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, "
                    "pg_has_role('saas_notification_dispatcher', "
                    "'saas_platform_governance', 'member'), "
                    "has_table_privilege('saas_notification_dispatcher', "
                    "'saas_notification_deliveries', 'SELECT'), "
                    "has_column_privilege('saas_notification_dispatcher', "
                    "'saas_notification_deliveries', 'status', 'UPDATE'), "
                    "has_column_privilege('saas_notification_dispatcher', "
                    "'saas_notification_deliveries', 'recipient_read_at', 'UPDATE'), "
                    "has_table_privilege('saas_notification_dispatcher', "
                    "'saas_notification_delivery_attempts', 'INSERT'), "
                    "has_table_privilege('saas_notification_dispatcher', "
                    "'saas_notification_deliveries', 'INSERT'), "
                    "has_column_privilege('saas_notification_dispatcher', "
                    "'saas_approval_work_items', 'status', 'SELECT'), "
                    "has_column_privilege('saas_notification_dispatcher', "
                    "'saas_approval_work_items', 'action', 'SELECT') "
                    "FROM pg_roles WHERE rolname = 'saas_notification_dispatcher'"
                )
            ).one()
            if tuple(notification_dispatcher_role) != (
                False,
                False,
                False,
                False,
                True,
                True,
                False,
                True,
                True,
                True,
                False,
            ):
                raise PostgreSqlRestoreContractError(
                    "restored notification dispatcher authority widened or drifted"
                )
            notification_directory_role = connection.execute(
                sa.text(
                    "SELECT rolcanlogin, rolsuper, rolbypassrls, "
                    "pg_has_role('saas_notification_directory', "
                    "'saas_platform_governance', 'member'), "
                    "pg_has_role('saas_notification_directory', "
                    "'saas_governance', 'member'), "
                    "pg_has_role('saas_notification_directory', "
                    "'saas_notification_dispatcher', 'member'), "
                    "pg_has_role('saas_notification_directory', "
                    "'saas_notification_scheduler', 'member'), "
                    "pg_has_role('saas_notification_directory', "
                    "'saas_platform', 'member'), "
                    "has_table_privilege('saas_notification_directory', "
                    "'saas_global_users', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_global_users', 'primary_email_normalized', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_global_users', 'security_version', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_platform_staff_principals', 'email_normalized', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_platform_staff_principals', 'issuer', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_platform_role_assignments', 'principal_id', 'SELECT'), "
                    "has_column_privilege('saas_notification_directory', "
                    "'saas_platform_role_assignments', "
                    "'assigned_by_principal_id', 'SELECT') "
                    "FROM pg_roles WHERE rolname = 'saas_notification_directory'"
                )
            ).one()
            if tuple(notification_directory_role) != (
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                True,
                False,
                True,
                False,
                True,
                False,
            ):
                raise PostgreSqlRestoreContractError(
                    "restored notification directory authority widened or drifted"
                )
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_app; "
                f"SET LOCAL app.actor_id = '{identifiers['actor_a']}'; "
                f"SET LOCAL app.tenant_id = '{identifiers['tenant_a']}'; "
                f"SET LOCAL app.space_id = '{identifiers['space_a']}'"
            )
            visible_tenants = set(
                connection.execute(sa.text("SELECT id::text FROM saas_tenants")).scalars()
            )
            if visible_tenants != {identifiers["tenant_a"]}:
                raise PostgreSqlRestoreContractError("restored SaaS RLS exposed another tenant")
            visible_groups = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_groups")
                ).scalars()
            )
            visible_custom_roles = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_custom_roles")
                ).scalars()
            )
            visible_preflights = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_access_preflights")
                ).scalars()
            )
            if (
                visible_groups != {identifiers["group_a"]}
                or visible_custom_roles != {identifiers["custom_role_a"]}
                or visible_preflights != {identifiers["enterprise_preflight_a"]}
            ):
                raise PostgreSqlRestoreContractError(
                    "restored enterprise access RLS exposed another tenant"
                )
            visible_scim_directories = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_directories")
                ).scalars()
            )
            visible_scim_users = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_users")
                ).scalars()
            )
            visible_scim_groups = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_groups")
                ).scalars()
            )
            if (
                visible_scim_directories != {identifiers["scim_directory_a"]}
                or visible_scim_users != {identifiers["scim_user_a"]}
                or visible_scim_groups != {identifiers["scim_group_a"]}
            ):
                raise PostgreSqlRestoreContractError(
                    "restored enterprise SCIM RLS exposed another tenant"
                )
            scim_reader_privileges = connection.execute(
                sa.text(
                    "SELECT "
                    "has_function_privilege(current_user, "
                    "'saas_scim_source_token_matches(uuid,uuid,text)', 'EXECUTE'), "
                    "has_column_privilege(current_user, "
                    "'saas_enterprise_scim_directories', 'token_hash', 'SELECT'), "
                    "has_column_privilege(current_user, "
                    "'saas_enterprise_scim_directories', "
                    "'successor_token_hash', 'SELECT')"
                )
            ).one()
            if tuple(scim_reader_privileges) != (True, False, False):
                raise PostgreSqlRestoreContractError(
                    "restored SCIM reader lost content-blind matching or gained bearer digests"
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_authenticator; "
                f"SET LOCAL app.privacy_locator_hash = "
                f"'{identifiers['privacy_locator_hash']}'"
            )
            visible_tombstones = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_privacy_identity_tombstones")
                ).scalars()
            )
            if visible_tombstones != {identifiers["privacy_tombstone"]}:
                raise PostgreSqlRestoreContractError(
                    "restored identity Tombstone exact-locator replay guard drifted"
                )
        with engine.begin() as connection:
            directory_privileges = connection.execute(
                sa.text(
                    "SELECT has_column_privilege('saas_app', "
                    "'saas_enterprise_scim_directories', 'token_hash', 'SELECT'), "
                    "has_column_privilege('saas_app', "
                    "'saas_enterprise_scim_directories', 'successor_token_hash', 'SELECT'), "
                    "has_table_privilege('saas_app', 'saas_enterprise_scim_events', 'SELECT')"
                )
            ).one()
            if tuple(directory_privileges) != (False, False, False):
                raise PostgreSqlRestoreContractError(
                    "application role can read SCIM bearer digests or immutable receipts"
                )
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_governance; "
                f"SET LOCAL app.scim_token_hash = '{identifiers['scim_token_hash_a']}'"
            )
            token_directories = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_directories")
                ).scalars()
            )
            token_users = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_users")
                ).scalars()
            )
            if token_directories != {identifiers["scim_directory_a"]} or token_users:
                raise PostgreSqlRestoreContractError(
                    "SCIM token lookup was not restricted before Tenant binding"
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_governance; "
                f"SET LOCAL app.scim_token_hash = "
                f"'{identifiers['scim_successor_token_hash_a']}'"
            )
            successor_directories = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_enterprise_scim_directories")
                ).scalars()
            )
            if successor_directories != {identifiers["scim_directory_a"]}:
                raise PostgreSqlRestoreContractError(
                    "SCIM successor token lookup was not restored under the Directory boundary"
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL ROLE saas_billing; "
                f"SET LOCAL app.tenant_id = '{identifiers['tenant_a']}'"
            )
            visible_metering_receipts = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_billing_metering_receipts")
                ).scalars()
            )
            if visible_metering_receipts != {identifiers["billing_metering_receipt_a"]}:
                raise PostgreSqlRestoreContractError(
                    "restored billing receipt RLS exposed another tenant"
                )
            visible_period_closes = set(
                connection.execute(
                    sa.text("SELECT id::text FROM saas_billing_period_closes")
                ).scalars()
            )
            if visible_period_closes != {identifiers["billing_period_close_a"]}:
                raise PostgreSqlRestoreContractError(
                    "restored billing period-close RLS exposed another tenant"
                )
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "SET LOCAL ROLE omnigent_runtime_app; "
                f"SET LOCAL app.runtime_workspace_id = '{identifiers['workspace_a']}'"
            )
            visible_runtime_users = set(
                connection.execute(sa.text("SELECT id FROM users")).scalars()
            )
            if visible_runtime_users != {"runtime-a"}:
                raise PostgreSqlRestoreContractError(
                    "restored Runtime RLS exposed another workspace"
                )
        with engine.connect() as connection:
            replay = connection.execute(
                sa.text(
                    "SELECT u.security_version, i.status, s.revoked_at IS NOT NULL, "
                    "tm.status, sm.status, t.status, machine.status, "
                    "machine.security_version, credential.status, "
                    "credential.revoked_at IS NOT NULL, gm.status, gra.status, "
                    "g.status, g.archived_at IS NOT NULL, g.archived_by::text, "
                    "r.status, r.retired_at IS NOT NULL, r.retired_by::text "
                    "FROM saas_global_users u "
                    "JOIN saas_identity_connections i ON i.user_id = u.id "
                    "JOIN saas_auth_sessions s ON s.user_id = u.id "
                    "JOIN saas_tenant_memberships tm ON tm.user_id = u.id "
                    "JOIN saas_space_memberships sm ON sm.user_id = u.id "
                    "JOIN saas_tenants t ON t.id = tm.tenant_id "
                    "JOIN saas_service_accounts machine ON machine.steward_user_id = u.id "
                    "AND machine.tenant_id = t.id "
                    "JOIN saas_api_credentials credential "
                    "ON credential.service_account_id = machine.id "
                    "JOIN saas_enterprise_group_memberships gm "
                    "ON gm.tenant_id = t.id AND gm.user_id = u.id "
                    "JOIN saas_enterprise_group_role_assignments gra "
                    "ON gra.tenant_id = t.id AND gra.group_id = gm.group_id "
                    "JOIN saas_enterprise_groups g ON g.id = gm.group_id "
                    "JOIN saas_enterprise_custom_roles r ON r.id = gra.custom_role_id "
                    "WHERE u.id = :actor_b"
                ),
                identifiers,
            ).one()
            if tuple(replay) != (
                2,
                "revoked",
                True,
                "removed",
                "removed",
                "pending_deletion",
                "suspended",
                2,
                "revoked",
                True,
                "removed",
                "revoked",
                "archived",
                True,
                identifiers["actor_b"],
                "retired",
                True,
                identifiers["actor_b"],
            ):
                raise PostgreSqlRestoreContractError(
                    "post-backup revocation/deletion replay is incomplete"
                )
            preflight_replay = connection.execute(
                sa.text(
                    "SELECT status, approved_by::text, executed_at IS NOT NULL "
                    "FROM saas_enterprise_access_preflights "
                    "WHERE id = :enterprise_preflight_b"
                ),
                identifiers,
            ).one()
            if tuple(preflight_replay) != (
                "executed",
                identifiers["approver_b"],
                True,
            ):
                raise PostgreSqlRestoreContractError(
                    "post-backup enterprise approval replay is incomplete"
                )
            billing_replay = connection.execute(
                sa.text(
                    "SELECT subscription.status, subscription.version, mismatch.status, "
                    "mismatch.resolution, mismatch.resolved_by::text, "
                    "mismatch.resolved_at IS NOT NULL, balance.available_minor, "
                    "balance.reserved_minor "
                    "FROM saas_billing_subscriptions subscription "
                    "JOIN saas_billing_reconciliation_mismatches mismatch "
                    "ON mismatch.tenant_id = subscription.tenant_id "
                    "JOIN saas_billing_balances balance "
                    "ON balance.tenant_id = subscription.tenant_id "
                    "WHERE subscription.id = :billing_subscription_b "
                    "AND mismatch.id = :billing_mismatch_b"
                ),
                identifiers,
            ).one()
            if tuple(billing_replay) != (
                "suspended",
                2,
                "resolved",
                "recovery replay verified",
                identifiers["actor_b"],
                True,
                90,
                10,
            ):
                raise PostgreSqlRestoreContractError(
                    "post-backup billing authority replay is incomplete"
                )
            metering_receipts = connection.execute(
                sa.text(
                    "SELECT receipt.id::text, receipt.tenant_id::text, usage.id::text, "
                    "run.id::text, capability.id::text, certificate.id::text, runner.id::text "
                    "FROM saas_billing_metering_receipts receipt "
                    "JOIN saas_usage_events usage "
                    "ON usage.tenant_id = receipt.tenant_id "
                    "AND usage.id = receipt.usage_event_id "
                    "JOIN saas_runs run ON run.tenant_id = receipt.tenant_id "
                    "AND run.space_id = receipt.space_id "
                    "AND run.project_id = receipt.project_id AND run.id = receipt.run_id "
                    "JOIN saas_capability_tokens capability "
                    "ON capability.id = receipt.capability_id "
                    "AND capability.run_id = receipt.run_id "
                    "AND capability.runner_id = receipt.runner_id "
                    "AND capability.runner_connection_generation = "
                    "receipt.runner_connection_generation "
                    "AND capability.dispatch_generation = receipt.dispatch_generation "
                    "AND capability.fence_token = receipt.fence_token "
                    "JOIN saas_runner_certificates certificate "
                    "ON certificate.id = receipt.runner_certificate_id "
                    "AND certificate.runner_id = receipt.runner_id "
                    "AND certificate.runner_connection_generation = "
                    "receipt.runner_connection_generation "
                    "AND certificate.purpose = 'billing_metering' "
                    "AND certificate.fingerprint_sha256 = "
                    "receipt.certificate_fingerprint_sha256 "
                    "JOIN saas_runner_registrations runner ON runner.id = receipt.runner_id "
                    "ORDER BY receipt.id"
                )
            ).all()
            expected_metering_links = {
                (
                    identifiers["billing_metering_receipt_a"],
                    identifiers["tenant_a"],
                    identifiers["usage_event_a"],
                    identifiers["run_a"],
                    identifiers["capability_a"],
                    identifiers["runner_certificate_a"],
                    identifiers["runner_a"],
                ),
                (
                    identifiers["billing_metering_receipt_b"],
                    identifiers["tenant_b"],
                    identifiers["usage_event_b"],
                    identifiers["run_b"],
                    identifiers["capability_b"],
                    identifiers["runner_certificate_b"],
                    identifiers["runner_b"],
                ),
            }
            if {tuple(row) for row in metering_receipts} != expected_metering_links:
                raise PostgreSqlRestoreContractError(
                    "restored machine metering authority links are incomplete"
                )
            metering_immutable_trigger = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_trigger trigger "
                    "JOIN pg_class relation ON relation.oid = trigger.tgrelid "
                    "WHERE relation.relname = 'saas_billing_metering_receipts' "
                    "AND trigger.tgname = 'trg_saas_billing_metering_receipts_immutable' "
                    "AND NOT trigger.tgisinternal"
                )
            ).scalar_one()
            if metering_immutable_trigger != 1:
                raise PostgreSqlRestoreContractError(
                    "restored machine metering receipt immutability trigger is missing"
                )
            period_close_rows = connection.execute(
                sa.text(
                    "SELECT id::text, tenant_id::text, reconciliation_batch_id::text, status "
                    "FROM saas_billing_period_closes ORDER BY id"
                )
            ).all()
            if {tuple(row) for row in period_close_rows} != {
                (
                    identifiers["billing_period_close_a"],
                    identifiers["tenant_a"],
                    identifiers["billing_reconciliation_a"],
                    "closed_with_resolved_exceptions",
                ),
                (
                    identifiers["billing_period_close_b"],
                    identifiers["tenant_b"],
                    identifiers["billing_reconciliation_b"],
                    "closed_with_resolved_exceptions",
                ),
            }:
                raise PostgreSqlRestoreContractError(
                    "restored nonempty billing period-close facts are incomplete"
                )
            period_close_immutable_trigger = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_trigger trigger "
                    "JOIN pg_class relation ON relation.oid = trigger.tgrelid "
                    "WHERE relation.relname = 'saas_billing_period_closes' "
                    "AND trigger.tgname = 'trg_saas_billing_period_closes_immutable' "
                    "AND NOT trigger.tgisinternal"
                )
            ).scalar_one()
            if period_close_immutable_trigger != 1:
                raise PostgreSqlRestoreContractError(
                    "restored billing period-close immutability trigger is missing"
                )
            scim_rows = connection.execute(
                sa.text(
                    "SELECT "
                    "(SELECT count(*) FROM saas_enterprise_scim_directories), "
                    "(SELECT count(*) FROM saas_enterprise_scim_users), "
                    "(SELECT count(*) FROM saas_enterprise_scim_groups), "
                    "(SELECT count(*) FROM saas_enterprise_scim_events), "
                    "(SELECT count(*) FROM saas_enterprise_scim_directories "
                    "WHERE successor_token_hash IS NOT NULL)"
                )
            ).one()
            if tuple(scim_rows) != (2, 2, 2, 3, 1):
                raise PostgreSqlRestoreContractError(
                    "restored nonempty enterprise SCIM facts are incomplete"
                )
            scim_immutable_trigger = connection.execute(
                sa.text(
                    "SELECT count(*) FROM pg_trigger trigger "
                    "JOIN pg_class relation ON relation.oid = trigger.tgrelid "
                    "WHERE relation.relname = 'saas_enterprise_scim_events' "
                    "AND trigger.tgname = 'trg_scim_event_immutable' "
                    "AND NOT trigger.tgisinternal"
                )
            ).scalar_one()
            if scim_immutable_trigger != 1:
                raise PostgreSqlRestoreContractError(
                    "restored SCIM event immutability trigger is missing"
                )
        return {
            "saas_migration_head": saas_head,
            "official_migration_heads": official_heads,
            "control_plane_forced_rls_tables": len(CONTROL_PLANE_RLS_TABLES),
            "runtime_forced_rls_tables": len(load_runtime_rls_contract()),
            "cross_tenant_negative_probe": "passed",
            "cross_tenant_billing_receipt_negative_probe": "passed",
            "cross_workspace_negative_probe": "passed",
            "post_backup_revocation_and_deletion_marker_replay": "passed",
            "post_backup_enterprise_lifecycle_replay": "passed",
            "post_backup_enterprise_approval_replay": "passed",
            "post_backup_billing_authority_replay": "passed",
            "machine_metering_receipt_restore": "passed",
            "billing_period_close_restore": "passed with one backed-up and one replayed fact",
            "enterprise_scim_restore": (
                "passed with two Tenant-isolated fact sets and one redacted receipt"
            ),
            "privacy_deletion_restore": (
                "passed with released Legal Hold, completed 15-surface Manifest, "
                "identity Tombstone, exact replay guard, and redacted SCIM receipt"
            ),
            "platform_security_restore": "passed",
        }
    finally:
        engine.dispose()


def _tool_version_major(tool: str) -> int | None:
    path = shutil.which(tool)
    if path is None:
        return None
    completed = subprocess.run(
        [path, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    match = re.search(r"(\d+)(?:\.\d+)?", completed.stdout)
    return int(match.group(1)) if completed.returncode == 0 and match else None


def _run_pg_tool(
    tool: str,
    endpoint: PostgreSqlEndpoint,
    database: str,
    archive: Path,
    *,
    server_major: int,
) -> str:
    _require_database_name(database)
    password_env = {**os.environ}
    if endpoint.password is not None:
        password_env["PGPASSWORD"] = endpoint.password
    host_tool = shutil.which(tool)
    if host_tool is not None and _tool_version_major(tool) == server_major:
        command_line = [
            host_tool,
            "--host",
            endpoint.host,
            "--port",
            str(endpoint.port),
            "--username",
            endpoint.username,
            "--no-password",
        ]
        if tool == "pg_dump":
            command_line.extend(
                [
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--file={archive}",
                    database,
                ]
            )
        else:
            command_line.extend(
                [
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    f"--dbname={database}",
                    str(archive),
                ]
            )
        implementation = f"host-postgresql-client-{server_major}"
    else:
        docker = shutil.which("docker")
        if docker is None:
            raise PostgreSqlRestoreContractError(
                f"PostgreSQL {server_major} client or Docker is required for the restore contract"
            )
        mounted_archive = f"/evidence/{archive.name}"
        command_line = [
            docker,
            "run",
            "--rm",
            "--network=host",
            f"--volume={archive.parent}:/evidence",
            "--env=PGPASSWORD",
            f"postgres:{server_major}",
            tool,
            "--host",
            endpoint.host,
            "--port",
            str(endpoint.port),
            "--username",
            endpoint.username,
            "--no-password",
        ]
        if tool == "pg_dump":
            command_line.extend(
                [
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--file={mounted_archive}",
                    database,
                ]
            )
        else:
            command_line.extend(
                [
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    f"--dbname={database}",
                    mounted_archive,
                ]
            )
        implementation = f"docker-postgres-{server_major}-client"
    completed = subprocess.run(
        command_line,
        check=False,
        capture_output=True,
        text=True,
        env=password_env,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout)[-4096:]
        raise PostgreSqlRestoreContractError(f"{tool} failed: {detail}")
    return implementation


def run_logical_restore_contract(
    repo: Path,
    admin_url: str,
    *,
    product_revision: str,
    allow_disposable_databases: bool = False,
) -> dict[str, Any]:
    """Execute the disposable logical restore and return non-production proof."""

    if not allow_disposable_databases:
        raise PostgreSqlRestoreContractError(
            "explicit disposable-database authorization is required"
        )
    if re.fullmatch(r"[0-9a-f]{40}", product_revision) is None:
        raise PostgreSqlRestoreContractError("product_revision must be a full Git SHA")
    endpoint = PostgreSqlEndpoint.parse(admin_url)
    migration_config = Config(repo / "saas/control_plane/alembic.ini")
    migration_config.set_main_option(
        "script_location",
        str(repo / "saas/control_plane/migrations"),
    )
    expected_saas_head = ScriptDirectory.from_config(migration_config).get_current_head()
    if expected_saas_head is None:
        raise PostgreSqlRestoreContractError("SaaS migration head is missing")
    admin_engine = sa.create_engine(endpoint.sqlalchemy_url(endpoint.admin_database))
    try:
        with admin_engine.connect() as connection:
            server_version_num = int(
                connection.exec_driver_sql("SHOW server_version_num").scalar_one()
            )
    finally:
        admin_engine.dispose()
    server_major = server_version_num // 10000
    if server_major < 14:
        raise PostgreSqlRestoreContractError(
            f"PostgreSQL server major {server_major} is below the supported restore baseline"
        )
    source_database = _database_name("restore_source")
    target_database = _database_name("restore_target")
    started = datetime.now(UTC)
    created: list[str] = []
    try:
        _create_database(endpoint, source_database)
        created.append(source_database)
        _migrate_source(repo, endpoint, source_database)
        identifiers = _seed_source(endpoint, source_database)
        with tempfile.TemporaryDirectory(prefix="omnigent-logical-restore-") as temporary:
            archive = Path(temporary) / "backup.dump"
            dump_client = _run_pg_tool(
                "pg_dump",
                endpoint,
                source_database,
                archive,
                server_major=server_major,
            )
            if not archive.is_file() or archive.stat().st_size <= 0:
                raise PostgreSqlRestoreContractError("pg_dump produced an empty archive")
            backup_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
            _apply_post_backup_replay(endpoint, source_database, identifiers)
            source_hash, source_counts = _database_digest(endpoint, source_database)
            _create_database(endpoint, target_database)
            created.append(target_database)
            restore_client = _run_pg_tool(
                "pg_restore",
                endpoint,
                target_database,
                archive,
                server_major=server_major,
            )
        target_engine = sa.create_engine(
            endpoint.sqlalchemy_url(target_database), poolclass=sa.pool.NullPool
        )
        try:
            with target_engine.begin() as connection:
                connection.exec_driver_sql(
                    (repo / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
                )
                connection.exec_driver_sql(
                    (repo / "saas/runtime_rls/postgresql_roles.sql").read_text(encoding="utf-8")
                )
        finally:
            target_engine.dispose()
        _apply_post_backup_replay(endpoint, target_database, identifiers)
        restored_facts = _verify_restored_database(
            endpoint,
            target_database,
            identifiers,
            expected_saas_head=expected_saas_head,
        )
        target_hash, target_counts = _database_digest(endpoint, target_database)
        if target_hash != source_hash or target_counts != source_counts:
            raise PostgreSqlRestoreContractError("restored selected-table content hash drifted")
        completed = datetime.now(UTC)
        return {
            "schema_version": 1,
            "contract": "ci-isolated-postgresql-logical-restore",
            "status": "pass",
            "evidence_kind": "ci_contract_not_production_drill",
            "product_revision": product_revision,
            "upstream_revision": str(
                json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))[
                    "upstream_revision"
                ]
            ),
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "duration_seconds": round((completed - started).total_seconds(), 3),
            "postgresql_client": dump_client,
            "postgresql_restore_client": restore_client,
            "backup_archive_sha256": backup_sha256,
            "selected_table_content_sha256": target_hash,
            "selected_table_row_counts": target_counts,
            **restored_facts,
            "source_and_restore_database_names_were_distinct": source_database != target_database,
            "temporary_databases_dropped_after_report": True,
            "not_proven": [
                "production data backup or restore",
                "WAL continuity or point-in-time recovery",
                "multi-AZ failover or another failure domain",
                "external KMS object lock backup retention or signed recovery evidence",
                "production Tenant or cluster RPO and RTO",
            ],
        }
    finally:
        for database in reversed(created):
            _drop_database(endpoint, database)
