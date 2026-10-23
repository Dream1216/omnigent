from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_test_funding import ModelTestFundingPolicy, ModelTestFundingService
from saas.control_plane.platform_security import PlatformAuthorizationService
from tests.saas.postgresql_retention import assert_retained_downgrade_refused
from tests.saas.test_model_connections import _fixture


def test_real_postgresql_platform_funding_and_billing_are_separate_authorities(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    owner = sa.create_engine(isolated_postgres_url)
    role_logins = {
        role: "test_funding_" + uuid4().hex for role in ("saas_platform_app", "saas_billing")
    }
    password = "isolated-funding-contract-only"
    quote = owner.dialect.identifier_preparer.quote
    database = sa.make_url(isolated_postgres_url).database
    assert database is not None
    engines = {}
    try:
        with owner.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            for role, login in role_logins.items():
                connection.exec_driver_sql(
                    f"CREATE ROLE {quote(login)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
                )
                connection.exec_driver_sql(
                    f"GRANT {role} TO {quote(login)} WITH INHERIT TRUE, SET FALSE"
                )
                connection.exec_driver_sql(
                    f"GRANT CONNECT ON DATABASE {quote(database)} TO {quote(login)}"
                )
        _connections, _factory, actor, _cipher, _client, _headers = _fixture(engine=owner)
        for role, login in role_logins.items():
            engines[role] = sa.create_engine(
                sa.make_url(isolated_postgres_url).set(username=login, password=password)
            )
        staff, billing = engines["saas_platform_app"], engines["saas_billing"]
        staff_factory = sessionmaker(staff, expire_on_commit=False)
        funding = ModelTestFundingService(
            staff, authorization=PlatformAuthorizationService(staff_factory)
        )
        policy = ModelTestFundingPolicy(True, 1000, 1000, 1000, 900, 900, 10)
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(
                pool.map(
                    lambda _index: funding.configure(actor, expected_version=0, policy=policy),
                    range(2),
                )
            )
        assert receipts[0] == receipts[1] and receipts[0].version == 1
        budget = ModelProviderBudgetAdmissionService(sessionmaker(billing, expire_on_commit=False))

        def reserve(_index):
            return budget.reserve_platform_test(
                verification_id=uuid4(),
                actor_principal_id=actor.principal_id,
                configuration_sha256="c" * 64,
                operation_key=uuid4().hex,
                requested_microusd=600,
                requested_tokens=700,
                ttl=timedelta(minutes=2),
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            reservations = list(pool.map(reserve, range(2)))
        assert sorted(row.status for row in reservations) == ["rejected", "reserved"]
        hold = next(row for row in reservations if row.status == "reserved")
        assert hold.tenant_id is None and hold.run_id is None
        budget.begin_attempt(reservation_id=hold.id)
        budget.mark_uncertain(reservation_id=hold.id)
        budget.resolve_attempt(
            reservation_id=hold.id,
            actual_microusd=450,
            actual_tokens=650,
            evidence_sha256="d" * 64,
        )
        with billing.connect() as connection:
            assert connection.scalar(sa.text("SELECT current_user")) == role_logins["saas_billing"]
            assert connection.exec_driver_sql(
                "SELECT reserved_microusd,settled_microusd "
                "FROM saas_model_provider_monthly_budgets"
            ).one() == (0, 450)
            assert (
                connection.scalar(
                    sa.text("SELECT COUNT(*) FROM saas_model_provider_tenant_daily_usage")
                )
                == 0
            )
        for engine, statement in (
            (staff, "UPDATE saas_model_test_funding_policies SET enabled=false"),
            (staff, "DELETE FROM saas_model_test_funding_policies"),
            (staff, "SELECT * FROM saas_model_provider_budget_reservations"),
            (billing, "INSERT INTO saas_model_test_funding_policies DEFAULT VALUES"),
            (billing, "SELECT api_key_ciphertext FROM saas_model_credential_versions"),
            (billing, "SET ROLE saas_platform_app"),
        ):
            with pytest.raises(DBAPIError) as denied, engine.connect() as connection:
                connection.exec_driver_sql(statement)
            assert getattr(denied.value.orig, "sqlstate", None) == "42501"
        disabled = funding.configure(
            actor, expected_version=1, policy=replace(policy, enabled=False)
        )
        assert disabled.version == 2
        assert_retained_downgrade_refused(
            owner, "lm1d00000001", expected_pattern="retained platform test funding evidence"
        )
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT COUNT(*) FROM pg_class WHERE relname IN "
                    "('saas_model_test_funding_policies', "
                    "'saas_model_provider_budget_reservations') "
                    "AND relforcerowsecurity"
                ).scalar_one()
                == 2
            )
    finally:
        for engine in engines.values():
            engine.dispose()
        with owner.begin() as connection:
            for role, login in role_logins.items():
                if connection.scalar(
                    sa.text("SELECT 1 FROM pg_roles WHERE rolname=:login"), {"login": login}
                ):
                    connection.exec_driver_sql(
                        f"REVOKE CONNECT ON DATABASE {quote(database)} FROM {quote(login)}"
                    )
                    connection.exec_driver_sql(f"REVOKE {role} FROM {quote(login)}")
                    connection.exec_driver_sql(f"DROP ROLE {quote(login)}")
        owner.dispose()
