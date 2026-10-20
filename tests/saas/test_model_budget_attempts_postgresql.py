from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.model_budget import (
    ModelProviderBudgetAdmissionService,
    ModelProviderBudgetError,
)
from saas.control_plane.platform_models import ModelProviderConfigurationRecord
from saas.control_plane.schema_revision import CONTROL_PLANE_SCHEMA_REVISION
from tests.saas.test_model_connections import _fixture


def test_real_postgresql_single_budget_attempt_keeps_unknown_costs_until_evidence(
    isolated_postgres_url: str,
) -> None:
    root = Path(__file__).resolve().parents[2]
    owner = sa.create_engine(isolated_postgres_url)
    login = "model_budget_attempt_" + uuid4().hex
    password = "isolated-model-budget-test-only"
    quoted = owner.dialect.identifier_preparer.quote
    database = sa.make_url(isolated_postgres_url).database
    assert database is not None
    billing: sa.Engine | None = None
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        with owner.begin() as connection:
            config = Config(root / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted(login)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                f"NOREPLICATION NOBYPASSRLS INHERIT PASSWORD '{password}'"
            )
            connection.exec_driver_sql(
                f"GRANT saas_billing TO {quoted(login)} WITH INHERIT TRUE, SET FALSE"
            )
            connection.exec_driver_sql(
                f"GRANT CONNECT ON DATABASE {quoted(database)} TO {quoted(login)}"
            )
        _connections, factory, actor, _cipher, _client, _headers = _fixture(engine=owner)
        with factory.begin() as db:
            db.add(
                ModelProviderConfigurationRecord(
                    provider_id="deepseek",
                    enabled=True,
                    base_url="https://api.deepseek.com",
                    api_type="openai_chat_completions",
                    api_key_ciphertext="not-a-provider-key",
                    allowed_models=["deepseek-isolated-contract"],
                    default_model="deepseek-isolated-contract",
                    monthly_budget_microusd=1000,
                    per_tenant_daily_token_limit=1000,
                    verification_status="verified",
                    last_verified_model="deepseek-isolated-contract",
                    last_verified_at=now,
                    version=1,
                    updated_by_principal_id=actor.principal_id,
                    updated_at=now,
                )
            )
        billing = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=login, password=password)
        )
        service = ModelProviderBudgetAdmissionService(
            sessionmaker(billing, expire_on_commit=False)
        )
        reservation = service.reserve(
            tenant_id=uuid4(),
            run_id=uuid4(),
            operation_key="one-durable-attempt",
            requested_microusd=900,
            requested_tokens=900,
            ttl=timedelta(minutes=1),
            now=now,
        )

        def begin(_index):
            try:
                return service.begin_attempt(reservation_id=reservation.id, now=now).status
            except ModelProviderBudgetError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            verdicts = list(pool.map(begin, range(2)))
        assert sorted(verdicts) == ["in_flight", "platform_model_budget_attempt_already_started"]
        future = now + timedelta(days=1)
        assert service.recover_expired(now=future) == ()
        unknown = service.mark_uncertain(reservation_id=reservation.id, now=future)
        assert unknown.status == "uncertain"
        assert service.recover_expired(now=future) == ()
        with pytest.raises(ModelProviderBudgetError):
            service.release(reservation_id=reservation.id, now=future)
        with billing.connect() as connection:
            assert connection.scalar(sa.text("SELECT current_user")) == login
            assert connection.exec_driver_sql(
                "SELECT reserved_microusd,settled_microusd "
                "FROM saas_model_provider_monthly_budgets"
            ).one() == (900, 0)

        def assert_evidence_cannot_be_removed():
            with pytest.raises(RuntimeError, match="retained model budget attempt evidence"):
                with owner.begin() as connection:
                    config.attributes["connection"] = connection
                    command.downgrade(config, "lm1c00000001")
            with owner.connect() as connection:
                assert (
                    connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                    == CONTROL_PLANE_SCHEMA_REVISION
                )
                assert connection.scalar(
                    sa.text(
                        "SELECT relforcerowsecurity FROM pg_class "
                        "WHERE oid = 'saas_model_provider_budget_reservations'::regclass"
                    )
                )

        assert_evidence_cannot_be_removed()
        outcome = {
            "reservation_id": reservation.id,
            "actual_microusd": 450,
            "actual_tokens": 650,
            "evidence_sha256": "e" * 64,
            "now": future,
        }
        assert service.resolve_attempt(**outcome).status == "settled"
        assert service.resolve_attempt(**outcome).replayed
        assert_evidence_cannot_be_removed()
        with billing.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT reserved_microusd,settled_microusd "
                "FROM saas_model_provider_monthly_budgets"
            ).one() == (0, 450)
            assert connection.exec_driver_sql(
                "SELECT status,outcome_evidence_sha256 "
                "FROM saas_model_provider_budget_reservations"
            ).one() == ("settled", "e" * 64)
        for statement in (
            "SELECT api_key_ciphertext FROM saas_model_provider_configurations",
            "SELECT * FROM saas_model_credential_versions",
            "SET ROLE saas_model_projection",
        ):
            with pytest.raises(DBAPIError) as denied, billing.connect() as connection:
                connection.exec_driver_sql(statement)
            assert getattr(denied.value.orig, "sqlstate", None) == "42501"
    finally:
        if billing is not None:
            billing.dispose()
        with owner.begin() as connection:
            if connection.scalar(
                sa.text("SELECT 1 FROM pg_roles WHERE rolname=:login"), {"login": login}
            ):
                connection.exec_driver_sql(
                    f"REVOKE CONNECT ON DATABASE {quoted(database)} FROM {quoted(login)}"
                )
                connection.exec_driver_sql(f"REVOKE saas_billing FROM {quoted(login)}")
                connection.exec_driver_sql(f"DROP ROLE {quoted(login)}")
        owner.dispose()
