from __future__ import annotations

from pathlib import Path

import pytest

from saas.control_plane.rls_inventory import CONTROL_PLANE_RLS_TABLES
from saas.production.postgresql_restore import (
    PostgreSqlEndpoint,
    PostgreSqlRestoreContractError,
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


def test_canonical_control_plane_rls_inventory_has_exactly_sixty_eight_tables() -> None:
    assert len(CONTROL_PLANE_RLS_TABLES) == 68
    assert "saas_service_accounts" in CONTROL_PLANE_RLS_TABLES
    assert "saas_api_credentials" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_groups" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_group_memberships" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_custom_roles" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_group_role_assignments" in CONTROL_PLANE_RLS_TABLES
    assert "saas_enterprise_access_preflights" in CONTROL_PLANE_RLS_TABLES
    assert "saas_webhook_endpoints" in CONTROL_PLANE_RLS_TABLES
    assert "saas_webhook_deliveries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_usage_events" in CONTROL_PLANE_RLS_TABLES
    assert "saas_customer_ledger_entries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_provider_cost_entries" in CONTROL_PLANE_RLS_TABLES
    assert "saas_billing_reconciliation_mismatches" in CONTROL_PLANE_RLS_TABLES
    assert "saas_billing_metering_receipts" in CONTROL_PLANE_RLS_TABLES
