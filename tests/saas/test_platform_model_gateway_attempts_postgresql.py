from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.platform_models import ModelProviderConfigurationRecord
from tests.saas.test_model_connections import _fixture as _staff_fixture
from tests.saas.test_platform_model_gateway_attempts import _body, _fixture, _row


@pytest.mark.parametrize("responses", (False, True))
def test_real_postgresql_gateway_uses_billing_login_for_one_sent_attempt(
    tmp_path, isolated_postgres_url, responses
):
    root = Path(__file__).resolve().parents[2]
    owner = sa.create_engine(isolated_postgres_url)
    login = "gateway_attempt_" + uuid4().hex
    password = "isolated-gateway-attempt-test-only"
    quoted = owner.dialect.identifier_preparer.quote
    database = sa.make_url(isolated_postgres_url).database
    billing = None
    created = False
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
        created = True
        _, factory, actor, _, _, _ = _staff_fixture(engine=owner)
        with factory.begin() as db:
            db.add(
                ModelProviderConfigurationRecord(
                    provider_id="deepseek",
                    enabled=True,
                    base_url="https://api.deepseek.com",
                    api_type="openai_chat_completions",
                    api_key_ciphertext="isolated-not-a-key",
                    allowed_models=["deepseek-flash"],
                    default_model="deepseek-flash",
                    monthly_budget_microusd=100_000_000,
                    per_tenant_daily_token_limit=100_000_000,
                    verification_status="verified",
                    last_verified_model="deepseek-flash",
                    last_verified_at=datetime.now(timezone.utc),
                    version=7,
                    updated_by_principal_id=actor.principal_id,
                    updated_at=datetime.now(timezone.utc),
                )
            )
        billing = sa.create_engine(
            sa.make_url(isolated_postgres_url).set(username=login, password=password)
        )
        budgets = ModelProviderBudgetAdmissionService(
            sessionmaker(billing, expire_on_commit=False)
        )
        calls = []

        def handler(_request):
            calls.append(_request)
            with billing.connect() as connection:
                assert connection.scalar(sa.text("SELECT current_user")) == login
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT status FROM saas_model_provider_budget_reservations "
                            "ORDER BY created_at DESC LIMIT 1"
                        )
                    )
                    == "in_flight"
                )
            return httpx.Response(
                200,
                content=_body(responses=responses, terminal=len(calls) == 1),
                headers={"content-type": "text/event-stream"},
            )

        client, path, request, _, _, _ = _fixture(
            tmp_path, handler, responses=responses, budget_database=(budgets, factory)
        )
        assert client.post(path, **request).status_code == 200
        row = _row(factory)
        assert row.status == "settled" and row.settled_microusd == row.settled_tokens == 13
        assert row.outcome_evidence_sha256 is not None
        assert budgets.resolve_attempt(
            reservation_id=row.id,
            actual_microusd=13,
            actual_tokens=13,
            evidence_sha256=row.outcome_evidence_sha256,
        ).replayed
        assert client.post(path, **request).status_code == 200
        assert budgets.recover_expired(now=datetime.now(timezone.utc) + timedelta(days=1)) == ()
        with billing.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT status,settled_microusd,settled_tokens,outcome_evidence_sha256 "
                "FROM saas_model_provider_budget_reservations ORDER BY created_at DESC LIMIT 1"
            ).one() == ("uncertain", 0, 0, None)
            held, settled = connection.exec_driver_sql(
                "SELECT reserved_microusd,settled_microusd "
                "FROM saas_model_provider_monthly_budgets"
            ).one()
            assert held > 0 and settled == 13
        for sql in (
            "SELECT api_key_ciphertext FROM saas_model_provider_configurations",
            "SELECT * FROM saas_model_credential_versions",
            "SET ROLE saas_model_projection",
        ):
            with pytest.raises(DBAPIError) as denied, billing.connect() as connection:
                connection.exec_driver_sql(sql)
            assert denied.value.orig.sqlstate == "42501"
        assert len(calls) == 2
    finally:
        if billing is not None:
            billing.dispose()
        if created:
            with owner.begin() as connection:
                connection.exec_driver_sql(
                    f"REVOKE CONNECT ON DATABASE {quoted(database)} FROM {quoted(login)}"
                )
                connection.exec_driver_sql(f"REVOKE saas_billing FROM {quoted(login)}")
                connection.exec_driver_sql(f"DROP ROLE {quoted(login)}")
        owner.dispose()
