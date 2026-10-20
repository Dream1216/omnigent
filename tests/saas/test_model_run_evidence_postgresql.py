from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from psycopg import Binary
from sqlalchemy.orm import sessionmaker

from saas.control_plane.billing_models import UsageEventRecord
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_document_storage import encode_model_document
from saas.control_plane.model_gateway_audit import ModelGatewayAuditPublisher
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_governed_models import PlatformAuditEventRecord
from saas.control_plane.platform_models import (
    ModelGatewayEvidenceRecord,
    ModelProviderBudgetReservationRecord,
    ModelProviderMonthlyBudgetRecord,
)
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production.model_run_credentials import ModelRunCredentialService
from tests.saas import test_tenant_model_catalog_postgresql
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_credentials_postgresql import _authenticator_login, _claim
from tests.saas.test_model_run_evidence import _enable_budget, _reserve
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@pytest.fixture(params=[False, True], autouse=True)
def publication_protocol(monkeypatch, request):
    original = test_tenant_model_catalog_postgresql._fixture
    monkeypatch.setattr(
        test_tenant_model_catalog_postgresql, "_fixture", lambda: original(responses=request.param)
    )


@contextmanager
def _billing_login(f):
    name = "run_budget_" + uuid4().hex[:16]
    password = "isolated-run-evidence-only"
    engine = None
    with f.engine.begin() as db:
        db.exec_driver_sql(
            f"CREATE ROLE {name} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE INHERIT"
        )
        db.exec_driver_sql(f"GRANT saas_billing TO {name} WITH INHERIT TRUE, SET FALSE")
        db.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {name}')
    try:
        engine = sa.create_engine(f.engine.url.set(username=name, password=password))
        with engine.connect() as db:
            assert db.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False)
            assert (
                db.exec_driver_sql("SELECT count(*) FROM saas_capability_tokens").scalar_one() == 0
            )
            assert not db.scalar(
                sa.text(
                    "SELECT has_table_privilege(current_user,'saas_model_run_tokens','SELECT')"
                )
            )
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        if engine is not None:
            engine.dispose()
        with f.engine.begin() as db:
            db.exec_driver_sql(f"DROP OWNED BY {name}")
            db.exec_driver_sql(f"DROP ROLE {name}")


def _grant(fixture, workers, authentication):
    f = fixture.base
    authority, authorized, lease, control, machine = _claim(
        fixture, workers, include_controller=True
    )
    service = ModelRunCredentialService(
        app_sessions=f.app_factory,
        authenticator_sessions=authentication,
        compatibility=authority._resolver._compatibility_policy,
    )
    issued = service.issue(authorized, lease)
    return service.authorize(service.authenticate(issued.value)), lease, control, machine


@pytest.mark.parametrize("zero", [False, True])
def test_actual_billing_login_retains_real_run_and_late_outcome_on_the_existing_audit_chain(
    interactive_postgresql,
    zero,
):
    f = interactive_postgresql.base
    with (
        _worker_logins(f) as workers,
        _authenticator_login(f) as authentication,
        _billing_login(f) as billing,
    ):
        grant, lease, control, machine = _grant(interactive_postgresql, workers, authentication)
        with billing() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(CapabilityTokenRecord)) == 0
        _enable_budget(f.factory)
        budgets = ModelProviderBudgetAdmissionService(billing)
        with f.factory() as db:
            previous_cost = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd))
        hold = _reserve(budgets, grant)
        assert hold.run_id == lease.run_id and hold.status == "reserved"
        budgets.begin_attempt(reservation_id=hold.id)
        budgets.mark_uncertain(reservation_id=hold.id)
        control.transition_run(
            **machine,
            run_id=lease.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            capability_token=lease.capability_token,
            target_status="succeeded",
        )
        usage = ModelTokenUsage(0, 0, 0, 0, 0) if zero else ModelTokenUsage(10, 0, 10, 3, 13)
        price = grant.gateway_request(output_token_limit=32).model_price
        kwargs = {
            "reservation_id": hold.id,
            "actual_microusd": price.cost(usage, at=datetime.now(timezone.utc)),
            "actual_tokens": usage.total_tokens,
            "evidence_sha256": None,
            "gateway_usage": usage,
        }
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(
                pool.map(lambda _: budgets.resolve_attempt(**kwargs).replayed, range(2))
            ) == [False, True]
        assert budgets.resolve_attempt(**kwargs).replayed
        facts = budgets.gateway_evidence(
            reservation_id=hold.id, tenant_id=hold.tenant_id, run_id=hold.run_id
        )
        assert [row.phase for row in facts] == [
            "request",
            "in_flight",
            "uncertain",
            "released" if zero else "settled",
        ]
        assert all(
            json.loads(row.canonical_evidence)["run_id"] == str(lease.run_id) for row in facts
        )
        with f.factory() as db:
            events = db.scalars(
                sa.select(ControlPlaneOutboxEvent).where(
                    ControlPlaneOutboxEvent.event_type == "model_gateway.evidence_retained"
                )
            ).all()
            assert len(events) == 4
            envelopes = [
                {
                    "event_id": e.id,
                    "event_type": e.event_type,
                    "aggregate_type": e.aggregate_type,
                    "aggregate_key": e.aggregate_key,
                    "payload": e.payload,
                }
                for e in events
            ]
            assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
            assert (
                db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd))
                == previous_cost + kwargs["actual_microusd"]
            )
            assert db.get(RunRecord, lease.run_id).status == "succeeded"
        audit = ModelGatewayAuditPublisher(workers["dispatcher"].kw["bind"], SimpleNamespace())
        audit.validate_outbox_configuration()
        for event in envelopes:
            audit.publish(**event)
            audit.publish(**event)
        with f.factory() as db:
            assert (
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(PlatformAuditEventRecord)
                    .where(
                        PlatformAuditEventRecord.event_type == "model_gateway.evidence_retained"
                    )
                )
                == 4
            )
        with (
            pytest.raises(RuntimeError, match="retained Run gateway evidence"),
            f.engine.begin() as db,
        ):
            config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = db
            command.downgrade(config, "lm2f00000001")
        for factory in (f.app_factory, authentication, workers["executor"]):
            with factory() as db:
                assert not db.scalar(
                    sa.text(
                        "SELECT has_function_privilege(current_user,"
                        "'public.saas_gateway_run_binding_v2(uuid,uuid,jsonb,timestamptz)',"
                        "'EXECUTE')"
                    )
                )


def test_database_rejects_cross_run_frozen_price_token_and_contract_tampering(
    interactive_postgresql,
):
    f = interactive_postgresql.base
    with (
        _worker_logins(f) as workers,
        _authenticator_login(f) as authentication,
        _billing_login(f) as billing,
    ):
        grant, lease, _control, _machine = _grant(interactive_postgresql, workers, authentication)
        _enable_budget(f.factory)
        budgets = ModelProviderBudgetAdmissionService(billing)

        def reject_corruption(name, value):
            def corrupt(_connection, _cursor, statement, parameters, _context, _executemany):
                if statement.startswith("INSERT INTO saas_model_gateway_evidence"):
                    document = json.loads(_context.compiled_parameters[0]["canonical_evidence"])
                    document["request"]["run_binding"][name] = value
                    raw = json.dumps(document, sort_keys=True, separators=(",", ":"))
                    parameters = {
                        **parameters,
                        "canonical_evidence": Binary(encode_model_document(raw)),
                        "evidence_sha256": sha256(raw.encode()).hexdigest(),
                    }
                return statement, parameters

            engine = billing.kw["bind"]
            sa.event.listen(engine, "before_cursor_execute", corrupt, retval=True)
            try:
                with pytest.raises(sa.exc.DBAPIError) as denied:
                    _reserve(budgets, grant, operation_key="tamper-" + name)
                assert denied.value.orig.sqlstate == "23514"
            finally:
                sa.event.remove(engine, "before_cursor_execute", corrupt)

        for name, value in (
            ("run_id", str(uuid4())),
            ("session_id", str(uuid4())),
            ("actor_id", str(uuid4())),
            ("customer_pricing_snapshot_id", str(uuid4())),
            ("capability_id", str(uuid4())),
            ("model_token_id", str(uuid4())),
            ("fence_token", lease.fence_token + 1),
            ("publication_generation", 2),
            ("publication_snapshot_sha256", "e" * 64),
        ):
            reject_corruption(name, value)
        with f.factory() as db:
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(ModelGatewayEvidenceRecord)) == 0
            )
            assert (
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(ModelProviderBudgetReservationRecord)
                    .where(ModelProviderBudgetReservationRecord.purpose == "tenant_run")
                )
                == 0
            )
            assert db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.reserved_microusd)) == 0
        hold = _reserve(budgets, grant)

        def downgrade_contract(
            _connection, _cursor, statement, parameters, _context, _executemany
        ):
            if statement.startswith("INSERT INTO saas_model_gateway_evidence"):
                document = json.loads(_context.compiled_parameters[0]["canonical_evidence"])
                document["contract"] = "platform-model-gateway-evidence-v1"
                document["session_id"] = document.pop("run_id")
                raw = json.dumps(document, sort_keys=True, separators=(",", ":"))
                parameters = {
                    **parameters,
                    "canonical_evidence": Binary(encode_model_document(raw)),
                    "evidence_sha256": sha256(raw.encode()).hexdigest(),
                }
            return statement, parameters

        engine = billing.kw["bind"]
        sa.event.listen(engine, "before_cursor_execute", downgrade_contract, retval=True)
        try:
            with pytest.raises(sa.exc.DBAPIError, match="contract changed"):
                budgets.begin_attempt(reservation_id=hold.id)
        finally:
            sa.event.remove(engine, "before_cursor_execute", downgrade_contract)
        with f.factory.begin() as db:
            cap = db.get(CapabilityTokenRecord, lease.capability_id)
            cap.revoked_at = datetime.now(timezone.utc)
            cap.revocation_reason = "isolated-real-revocation"
        with pytest.raises(sa.exc.DBAPIError, match="sequence rejected"):
            budgets.begin_attempt(reservation_id=hold.id)
        with f.factory() as db:
            assert db.get(ModelProviderBudgetReservationRecord, hold.id).status == "reserved"
        assert budgets.release(reservation_id=hold.id).status == "released"
        with pytest.raises(sa.exc.DBAPIError, match="request authority rejected"):
            _reserve(budgets, grant, operation_key="revoked-run-new-call")
