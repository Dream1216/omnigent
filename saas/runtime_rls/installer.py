"""Drift-checked PostgreSQL RLS installer for official runtime tables."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Connection

from omnigent.db import ConversationBase, OmnigentBase

RUNTIME_RLS_POLICY_NAME = "omnigent_runtime_workspace_isolation"
RUNTIME_RLS_ACCESS_POLICY_NAME = "omnigent_runtime_workspace_access"
_WORKSPACE_SETTING = "app.runtime_workspace_id"
_SAFE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")


class RuntimeRlsContractError(RuntimeError):
    """The reviewed Runtime RLS contract does not match source or database."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class RuntimeRlsTableContract:
    """Reviewed table name and exact primary-key column sequence."""

    table_name: str
    primary_key_columns: tuple[str, ...]


def load_runtime_rls_contract() -> tuple[RuntimeRlsTableContract, ...]:
    """Load the reviewed contract embedded in the installed SaaS package."""

    baseline_path = files("saas").joinpath("upstream-baseline.json")
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    raw_tables = payload.get("runtime_rls_tables")
    if not isinstance(raw_tables, dict) or not raw_tables:
        raise RuntimeRlsContractError(
            "runtime_rls_contract_missing",
            "upstream baseline does not contain a Runtime RLS table contract",
        )

    contracts: list[RuntimeRlsTableContract] = []
    for table_name, raw_primary_key in sorted(raw_tables.items()):
        if not isinstance(table_name, str) or not _SAFE_IDENTIFIER.fullmatch(table_name):
            raise RuntimeRlsContractError(
                "runtime_rls_identifier_invalid",
                "Runtime RLS contract contains an unsafe table identifier",
            )
        if (
            not isinstance(raw_primary_key, list)
            or not raw_primary_key
            or any(
                not isinstance(column, str) or not _SAFE_IDENTIFIER.fullmatch(column)
                for column in raw_primary_key
            )
        ):
            raise RuntimeRlsContractError(
                "runtime_rls_primary_key_invalid",
                f"Runtime RLS contract has an invalid primary key for {table_name}",
            )
        contracts.append(RuntimeRlsTableContract(table_name, tuple(raw_primary_key)))
    return tuple(contracts)


def _official_metadata_tables() -> dict[str, sa.Table]:
    tables: dict[str, sa.Table] = {}
    for metadata in (OmnigentBase.metadata, ConversationBase.metadata):
        for table in metadata.tables.values():
            if table.schema is None:
                tables[table.name] = table
    return tables


def _validate_source_contract(
    contracts: tuple[RuntimeRlsTableContract, ...],
) -> None:
    source_tables = _official_metadata_tables()
    reviewed_names = {contract.table_name for contract in contracts}
    workspace_owned_names = {
        table_name for table_name, table in source_tables.items() if "workspace_id" in table.c
    }
    if workspace_owned_names != reviewed_names:
        missing = sorted(workspace_owned_names - reviewed_names)
        stale = sorted(reviewed_names - workspace_owned_names)
        raise RuntimeRlsContractError(
            "runtime_rls_source_coverage_drift",
            f"Runtime RLS source coverage drifted: unreviewed={missing}, stale={stale}",
        )
    for contract in contracts:
        table = source_tables.get(contract.table_name)
        if table is None:
            raise RuntimeRlsContractError(
                "runtime_rls_source_table_drift",
                f"official source no longer defines {contract.table_name}",
            )
        if "workspace_id" not in table.c:
            raise RuntimeRlsContractError(
                "runtime_rls_source_partition_drift",
                f"official source table {contract.table_name} has no workspace_id",
            )
        actual_primary_key = tuple(column.name for column in table.primary_key.columns)
        if actual_primary_key != contract.primary_key_columns:
            raise RuntimeRlsContractError(
                "runtime_rls_source_primary_key_drift",
                f"official source primary key drifted for {contract.table_name}: "
                f"expected {contract.primary_key_columns}, got {actual_primary_key}",
            )


def _validate_database_contract(
    connection: Connection,
    contracts: tuple[RuntimeRlsTableContract, ...],
) -> None:
    inspector = sa.inspect(connection)
    for contract in contracts:
        if not inspector.has_table(contract.table_name, schema="public"):
            raise RuntimeRlsContractError(
                "runtime_rls_database_table_drift",
                f"database does not contain reviewed table public.{contract.table_name}",
            )
        columns = {column["name"]: column for column in inspector.get_columns(contract.table_name)}
        workspace_column = columns.get("workspace_id")
        if workspace_column is None:
            raise RuntimeRlsContractError(
                "runtime_rls_database_partition_drift",
                f"database table {contract.table_name} has no workspace_id",
            )
        if not isinstance(workspace_column["type"], sa.BigInteger):
            raise RuntimeRlsContractError(
                "runtime_rls_database_partition_type_drift",
                f"database table {contract.table_name}.workspace_id is not BIGINT",
            )
        primary_key = inspector.get_pk_constraint(contract.table_name)
        actual_primary_key = tuple(primary_key.get("constrained_columns") or ())
        if actual_primary_key != contract.primary_key_columns:
            raise RuntimeRlsContractError(
                "runtime_rls_database_primary_key_drift",
                f"database primary key drifted for {contract.table_name}: "
                f"expected {contract.primary_key_columns}, got {actual_primary_key}",
            )


def _require_postgresql(connection: Connection) -> None:
    if connection.dialect.name != "postgresql":
        raise RuntimeRlsContractError(
            "runtime_rls_postgresql_required",
            "Runtime RLS can only be installed on PostgreSQL",
        )


def _quote(connection: Connection, identifier: str) -> str:
    return connection.dialect.identifier_preparer.quote(identifier)


def _reject_unmanaged_policies(
    connection: Connection,
    contracts: tuple[RuntimeRlsTableContract, ...],
) -> None:
    managed_names = {RUNTIME_RLS_ACCESS_POLICY_NAME, RUNTIME_RLS_POLICY_NAME}
    rows = connection.execute(
        sa.text(
            """
            SELECT tablename, policyname
            FROM pg_policies
            WHERE schemaname = 'public' AND tablename = ANY(:table_names)
            """
        ),
        {"table_names": [contract.table_name for contract in contracts]},
    ).all()
    unmanaged = sorted(
        (table_name, policy_name)
        for table_name, policy_name in rows
        if policy_name not in managed_names
    )
    if unmanaged:
        raise RuntimeRlsContractError(
            "runtime_rls_unmanaged_policy",
            f"reviewed Runtime tables contain unmanaged policies: {unmanaged}",
        )


def install_runtime_rls(connection: Connection) -> None:
    """Install or replace fail-closed policies after source and DB validation."""

    _require_postgresql(connection)
    contracts = load_runtime_rls_contract()
    _validate_source_contract(contracts)
    _validate_database_contract(connection, contracts)
    _reject_unmanaged_policies(connection, contracts)

    access_policy = _quote(connection, RUNTIME_RLS_ACCESS_POLICY_NAME)
    boundary_policy = _quote(connection, RUNTIME_RLS_POLICY_NAME)
    predicate = f"workspace_id = NULLIF(current_setting('{_WORKSPACE_SETTING}', true), '')::bigint"
    for contract in contracts:
        table = _quote(connection, contract.table_name)
        connection.exec_driver_sql(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        connection.exec_driver_sql(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
        connection.exec_driver_sql(f"DROP POLICY IF EXISTS {access_policy} ON public.{table}")
        connection.exec_driver_sql(f"DROP POLICY IF EXISTS {boundary_policy} ON public.{table}")
        connection.exec_driver_sql(
            f"CREATE POLICY {access_policy} ON public.{table} "
            f"AS PERMISSIVE FOR ALL TO PUBLIC USING ({predicate}) "
            f"WITH CHECK ({predicate})"
        )
        connection.exec_driver_sql(
            f"CREATE POLICY {boundary_policy} ON public.{table} "
            f"AS RESTRICTIVE FOR ALL TO PUBLIC USING ({predicate}) "
            f"WITH CHECK ({predicate})"
        )
    verify_runtime_rls(connection, contracts=contracts)


def verify_runtime_rls(
    connection: Connection,
    *,
    contracts: tuple[RuntimeRlsTableContract, ...] | None = None,
) -> None:
    """Fail unless every reviewed table has the exact forced isolation policy."""

    _require_postgresql(connection)
    reviewed = contracts or load_runtime_rls_contract()
    _validate_source_contract(reviewed)
    _validate_database_contract(connection, reviewed)
    _reject_unmanaged_policies(connection, reviewed)

    rows = connection.execute(
        sa.text(
            """
            SELECT c.relname,
                   c.relrowsecurity,
                   c.relforcerowsecurity,
                   p.polname AS policy_name,
                   p.polcmd,
                   p.polpermissive,
                   p.polroles,
                   pg_get_expr(p.polqual, p.polrelid) AS using_expression,
                   pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            LEFT JOIN pg_policy AS p ON p.polrelid = c.oid
            WHERE n.nspname = 'public' AND c.relname = ANY(:table_names)
            """
        ),
        {
            "table_names": [contract.table_name for contract in reviewed],
        },
    ).mappings()
    by_table: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_table.setdefault(row["relname"], []).append(dict(row))

    for contract in reviewed:
        table_rows = by_table.get(contract.table_name, [])
        if (
            not table_rows
            or not table_rows[0]["relrowsecurity"]
            or not table_rows[0]["relforcerowsecurity"]
        ):
            raise RuntimeRlsContractError(
                "runtime_rls_not_forced",
                f"Runtime RLS is not enabled and forced for {contract.table_name}",
            )
        policies = {
            row.get("policy_name"): row for row in table_rows if row.get("policy_name") is not None
        }
        expected_permissive = {
            RUNTIME_RLS_ACCESS_POLICY_NAME: True,
            RUNTIME_RLS_POLICY_NAME: False,
        }
        if set(policies) != set(expected_permissive):
            raise RuntimeRlsContractError(
                "runtime_rls_policy_drift",
                f"Runtime RLS policy drifted for {contract.table_name}",
            )
        for policy_name, permissive in expected_permissive.items():
            row = policies[policy_name]
            expressions = (row["using_expression"], row["check_expression"])
            if (
                row["polcmd"] != "*"
                or row["polpermissive"] is not permissive
                or row["polroles"] != [0]
                or any(
                    not isinstance(expression, str)
                    or _WORKSPACE_SETTING not in expression
                    or "workspace_id" not in expression
                    for expression in expressions
                )
            ):
                raise RuntimeRlsContractError(
                    "runtime_rls_policy_drift",
                    f"Runtime RLS policy drifted for {contract.table_name}",
                )


def remove_runtime_rls(connection: Connection) -> None:
    """Explicit deployment rollback for only the SaaS-owned Runtime RLS policy."""

    _require_postgresql(connection)
    contracts = load_runtime_rls_contract()
    _validate_source_contract(contracts)
    _validate_database_contract(connection, contracts)
    access_policy = _quote(connection, RUNTIME_RLS_ACCESS_POLICY_NAME)
    boundary_policy = _quote(connection, RUNTIME_RLS_POLICY_NAME)
    for contract in contracts:
        table = _quote(connection, contract.table_name)
        connection.exec_driver_sql(f"DROP POLICY IF EXISTS {access_policy} ON public.{table}")
        connection.exec_driver_sql(f"DROP POLICY IF EXISTS {boundary_policy} ON public.{table}")
        connection.exec_driver_sql(f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY")
        connection.exec_driver_sql(f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY")
