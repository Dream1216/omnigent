from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from saas.control_plane.onboarding import OnboardingPlan
from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.production.postgresql_restore import (
    _SELECTED_HASH_TABLES,
    PostgreSqlEndpoint,
    PostgreSqlRestoreContractError,
    _canonical_json_sha256,
    _recovery_plan_snapshot,
    _recovery_runtime_target,
    run_logical_restore_contract,
)


def test_postgresql_endpoint_requires_explicit_tcp_admin_coordinates() -> None:
    endpoint = PostgreSqlEndpoint.parse(
        "postgresql+psycopg://restore-user:p%40ss@127.0.0.1:5432/postgres"
    )

    assert endpoint.username == "restore-user"
    assert endpoint.password == "p@ss"
    assert endpoint.host == "127.0.0.1"
    assert endpoint.port == 5432
    assert endpoint.admin_database == "postgres"
    assert endpoint.sqlalchemy_url("isolated_restore").database == "isolated_restore"


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///restore.db",
        "postgresql+psycopg:///postgres",
        "postgresql+psycopg://user@localhost/postgres",
        "postgresql+psycopg://user@localhost:5432/postgres?sslmode=disable",
    ],
)
def test_postgresql_endpoint_rejects_ambiguous_or_non_postgresql_urls(url: str) -> None:
    with pytest.raises(PostgreSqlRestoreContractError):
        PostgreSqlEndpoint.parse(url)


def test_restore_contract_rejects_non_exact_product_revision_before_connecting() -> None:
    with pytest.raises(PostgreSqlRestoreContractError, match="full Git SHA"):
        run_logical_restore_contract(
            Path.cwd(),
            "postgresql+psycopg://user:password@127.0.0.1:5432/postgres",
            product_revision="short",
            allow_disposable_databases=True,
        )


def test_restore_contract_requires_explicit_disposable_database_authorization() -> None:
    with pytest.raises(PostgreSqlRestoreContractError, match="explicit disposable"):
        run_logical_restore_contract(
            Path.cwd(),
            "postgresql+psycopg://user:password@127.0.0.1:5432/postgres",
            product_revision="a" * 40,
        )


def test_restore_fixture_uses_current_vertical_onboarding_plan_contract() -> None:
    plan = OnboardingPlan(
        key="test",
        policy_revision="recovery-plan-v1",
        trial_days=14,
    )

    assert _recovery_plan_snapshot() == plan.snapshot()
    assert _canonical_json_sha256(_recovery_plan_snapshot()) == plan.snapshot_hash()


def test_restore_fixture_freezes_a_complete_runtime_target() -> None:
    placement_id = UUID("95000000-0000-4000-8000-000000000001")

    target = _recovery_runtime_target({"runtime_placement": str(placement_id)})

    assert target == {
        "schema_version": 2,
        "placement_id": str(placement_id),
        "runtime_type": "omnigent",
        "data_region": "region-a",
        "failure_domain": "region-a-1",
        "official_schema_revision": "runtime-schema-v1",
        "capacity_class": "starter",
        "provider_binding": {
            "provider_type": "restore-contract-provider",
            "binding_revision": "restore-binding-v1",
            "binding_hash": "b" * 64,
        },
    }
    assert len(_canonical_json_sha256(target)) == 64


def test_restore_digest_covers_onboarding_activation_evidence_tables() -> None:
    assert {
        "saas_self_service_registrations",
        "saas_tenant_onboardings",
        "saas_self_service_events",
        "saas_projects",
        "saas_project_memberships",
        "saas_runtime_placements",
        "saas_runtime_partitions",
        "saas_runtime_resource_bindings",
        "saas_runtime_provider_operation_journal",
        "saas_admission_quotas",
        "saas_quota_reservations",
        "saas_runs",
        "saas_run_events",
    }.issubset(_SELECTED_HASH_TABLES)


def test_canonical_control_plane_rls_inventory_has_exactly_one_hundred_nine_tables() -> None:
    assert len(CONTROL_PLANE_RLS_TABLES) == 109
    assert "saas_runtime_provider_operation_journal" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_lifecycle_operations" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_staff_principals" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_role_assignments" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_auth_sessions" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_tenant_projections" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_user_projections" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_admin_operations" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_support_grants" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_support_sessions" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_audit_chain_heads" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_audit_events" in CONTROL_PLANE_RLS_TABLES
    assert "saas_platform_audit_exports" in CONTROL_PLANE_RLS_TABLES
    assert "saas_service_accounts" in CONTROL_PLANE_RLS_TABLES
    assert "saas_api_credentials" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_groups" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_group_memberships" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_custom_roles" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_group_role_assignments" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_access_preflights" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_scim_directories" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_scim_users" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_scim_groups" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_scim_events" in CONTROL_PLANE_RLS_TABLES
    assert "saas_webhook_endpoints" in CONTROL_PLANE_RLS_TABLES
    assert "saas_webhook_deliveries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_usage_events" in CONTROL_PLANE_RLS_TABLES
    assert "saas_customer_ledger_entries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_provider_cost_entries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_billing_reconciliation_mismatches" in CONTROL_PLANE_RLS_TABLES
    assert "saas_billing_period_closes" in CONTROL_PLANE_RLS_TABLES
    assert "saas_billing_metering_receipts" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_legal_holds" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_deletion_manifests" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_identity_tombstones" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_approval_bindings" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_deletion_work_items" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_deletion_attempts" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_evidence_attestations" in CONTROL_PLANE_RLS_TABLES
    assert "saas_privacy_backup_retention_items" in CONTROL_PLANE_RLS_TABLES
    assert "saas_approval_work_items" in CONTROL_PLANE_RLS_TABLES
    assert "saas_notification_deliveries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_operation_batch_items" in CONTROL_PLANE_RLS_TABLES
    assert "saas_self_service_registrations" in CONTROL_PLANE_RLS_TABLES
    assert "saas_email_verification_challenges" in CONTROL_PLANE_RLS_TABLES
    assert "saas_tenant_onboardings" in CONTROL_PLANE_RLS_TABLES
    assert "saas_self_service_events" in CONTROL_PLANE_RLS_TABLES
