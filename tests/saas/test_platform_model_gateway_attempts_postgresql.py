from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from psycopg import Binary
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from saas.control_plane.db_models import ControlPlaneOutboxEvent, Tenant
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_document_storage import encode_model_document
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import (
    ModelProviderConfigurationRecord,
)
from saas.control_plane.schema_revision import CONTROL_PLANE_SCHEMA_REVISION
from tests.saas.test_model_connections import _fixture as _staff_fixture
from tests.saas.test_platform_model_gateway import SESSION_ID, TENANT_ID
from tests.saas.test_platform_model_gateway_attempts import _body, _fixture, _row


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize("zero", (False, True))
def test_real_postgresql_gateway_uses_billing_login_for_one_sent_attempt(
    tmp_path, isolated_postgres_url, responses, zero
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
        outcome_visible = []

        def observe_outcome(connection, _cursor, statement, parameters, _context, _executemany):
            if (
                statement.startswith("INSERT INTO saas_model_gateway_evidence")
                and parameters["phase"] in {"settled", "released"}
                and json.loads(_context.compiled_parameters[0]["canonical_evidence"])["usage"]
                is not None
            ):
                retained = connection.execute(
                    sa.text(
                        "SELECT outcome_evidence_sha256 "
                        "FROM saas_model_provider_budget_reservations WHERE id=:id"
                    ),
                    {"id": parameters["reservation_id"]},
                ).scalar_one()
                outcome_visible.append(retained == parameters["evidence_sha256"])

        sa.event.listen(billing, "before_cursor_execute", observe_outcome)

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
            body = _body(responses=responses, terminal=len(calls) == 1)
            if zero:
                body = body.replace(b":10", b":0").replace(b":3", b":0").replace(b":13", b":0")
            return httpx.Response(
                200,
                content=body,
                headers={"content-type": "text/event-stream"},
            )

        client, path, request, _, _, _ = _fixture(
            tmp_path, handler, responses=responses, budget_database=(budgets, factory)
        )

        def corrupt_wire(_connection, _cursor, statement, parameters, _context, _executemany):
            if (
                statement.startswith("INSERT INTO saas_model_gateway_evidence")
                and parameters["phase"] == "request"
            ):
                value = json.loads(_context.compiled_parameters[0]["canonical_evidence"])
                value["request"]["wire_api"] = None
                canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
                parameters = {
                    **parameters,
                    "canonical_evidence": Binary(encode_model_document(canonical)),
                    "evidence_sha256": sha256(canonical.encode()).hexdigest(),
                }
            return statement, parameters

        rejected_codes = []

        def record_rejection(context):
            rejected_codes.append(context.original_exception.sqlstate)

        sa.event.listen(billing, "before_cursor_execute", corrupt_wire, retval=True)
        sa.event.listen(billing, "handle_error", record_rejection)
        try:
            assert client.post(path, **request).status_code == 503
            assert calls == []
            assert rejected_codes == ["23514"]
            with billing.connect() as connection:
                for table in (
                    "saas_model_provider_budget_reservations",
                    "saas_model_gateway_evidence",
                    "saas_model_provider_monthly_budgets",
                ):
                    assert (
                        connection.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar() == 0
                    )
        finally:
            sa.event.remove(billing, "before_cursor_execute", corrupt_wire)
            sa.event.remove(billing, "handle_error", record_rejection)
        assert client.post(path, **request).status_code == 200
        assert outcome_visible == [True]
        row = _row(factory)
        actual = 0 if zero else 13
        status = "released" if zero else "settled"
        assert row.status == status and row.settled_microusd == row.settled_tokens == actual
        assert row.outcome_evidence_sha256 is not None
        facts = budgets.gateway_evidence(
            reservation_id=row.id, tenant_id=TENANT_ID, run_id=SESSION_ID
        )
        assert [fact.phase for fact in facts] == ["request", "in_flight", status]
        assert facts[-1].evidence_sha256 == row.outcome_evidence_sha256
        assert budgets.resolve_attempt(
            reservation_id=row.id,
            actual_microusd=actual,
            actual_tokens=actual,
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
            assert held > 0 and settled == actual
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_model_gateway_evidence")) == 6
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE event_type='model_gateway.evidence_retained'"
                    )
                )
                == 6
            )
            pending = connection.exec_driver_sql(
                "SELECT id FROM saas_model_provider_budget_reservations WHERE status='uncertain'"
            ).scalar_one()
        usage = ModelTokenUsage(0, 0, 0, 0, 0) if zero else ModelTokenUsage(10, 0, 10, 3, 13)

        def resolve(_index):
            return budgets.resolve_attempt(
                reservation_id=pending,
                actual_microusd=actual,
                actual_tokens=actual,
                evidence_sha256=None,
                gateway_usage=usage,
            ).replayed

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(resolve, range(2))) == [False, True]
        with billing.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT reserved_microusd,settled_microusd "
                "FROM saas_model_provider_monthly_budgets"
            ).one() == (0, actual * 2)
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_model_gateway_evidence")) == 7
            )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM saas_control_plane_outbox "
                        "WHERE event_type='model_gateway.evidence_retained'"
                    )
                )
                == 7
            )
        assert outcome_visible == [True, True]
        with pytest.raises(DBAPIError) as immutable, owner.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE saas_model_gateway_evidence SET canonical_evidence='{}'"
            )
        assert immutable.value.orig.sqlstate == "23514"
        with pytest.raises(DBAPIError) as denied, billing.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE saas_model_gateway_evidence SET canonical_evidence='{}'"
            )
        assert denied.value.orig.sqlstate == "42501"
        with (
            pytest.raises(RuntimeError, match="retained gateway evidence"),
            owner.begin() as connection,
        ):
            config.attributes["connection"] = connection
            command.downgrade(config, "lm2a00000001")
        with owner.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version"))
                == CONTROL_PLANE_SCHEMA_REVISION
            )
            assert connection.scalar(
                sa.text(
                    "SELECT relforcerowsecurity FROM pg_class "
                    "WHERE oid='saas_model_gateway_evidence'::regclass"
                )
            )
            assert (
                connection.scalar(sa.text("SELECT count(*) FROM saas_customer_ledger_entries"))
                == 0
            )
        with factory.begin() as db:
            other = uuid4()
            db.add(
                Tenant(
                    id=other,
                    slug="other-" + other.hex,
                    name="Other fixture",
                    status="active",
                    plan="test",
                    home_region="test",
                )
            )
        with factory() as db:
            event = db.scalar(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == "model_gateway.evidence_retained"
                )
            )
        with pytest.raises(DBAPIError) as foreign, sessionmaker(billing).begin() as db:
            db.add(
                ControlPlaneOutboxEvent(
                    id=uuid4(),
                    tenant_id=other,
                    aggregate_type=event.aggregate_type,
                    aggregate_key=event.aggregate_key,
                    event_type=event.event_type,
                    payload={**event.payload, "tenant_id": str(other)},
                    idempotency_key=event.idempotency_key,
                    request_hash=event.request_hash,
                    attempt_count=0,
                )
            )
        assert foreign.value.orig.sqlstate == "42501"
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


def test_real_postgresql_empty_gateway_downgrade_restores_previous_authority(
    isolated_postgres_url,
):
    owner = sa.create_engine(isolated_postgres_url)
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    try:
        with owner.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            command.downgrade(config, "lm2a00000001")
            assert (
                connection.scalar(
                    sa.text("SELECT to_regclass('public.saas_model_gateway_evidence')")
                )
                is None
            )
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            command.upgrade(config, "head")
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            assert connection.scalar(
                sa.text(
                    "SELECT relforcerowsecurity FROM pg_class "
                    "WHERE oid='saas_model_gateway_evidence'::regclass"
                )
            )
    finally:
        owner.dispose()
