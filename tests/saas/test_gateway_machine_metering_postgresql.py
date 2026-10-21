from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from time import sleep
from types import SimpleNamespace
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import sessionmaker

from saas.billing_metering_transport import (
    BillingMeteringTransportError,
    MutualTlsBillingMeteringClient,
    MutualTlsBillingMeteringServer,
)
from saas.control_plane.billing import BillingControlPlane
from saas.control_plane.billing_metering import BillingMeteringAuthority
from saas.control_plane.billing_models import BillingMeteringReceiptRecord, UsageEventRecord
from saas.control_plane.certificates import RunnerCertificateAuthority
from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_usage import ModelTokenUsage
from saas.control_plane.platform_models import ModelProviderMonthlyBudgetRecord
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from tests.saas.test_billing_metering_transport import (
    _client_context,
    _server_context,
    _ServerThread,
)
from tests.saas.test_gateway_machine_metering import (
    _customer_prices,
    _register_metering_certificate,
    _request,
)
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_credentials_postgresql import _authenticator_login
from tests.saas.test_model_run_evidence import _enable_budget, _reserve
from tests.saas.test_model_run_evidence_postgresql import (
    _billing_login,
    _grant,
)
from tests.saas.test_model_run_evidence_postgresql import (
    publication_protocol as publication_protocol,
)
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@contextmanager
def _metering_login(f):
    name = "gateway_meter_" + uuid4().hex[:16]
    password = "isolated-gateway-meter-only"
    engine = None
    with f.engine.begin() as db:
        db.exec_driver_sql(
            f"CREATE ROLE {name} LOGIN PASSWORD '{password}' NOSUPERUSER NOBYPASSRLS "
            "NOCREATEDB NOCREATEROLE INHERIT"
        )
        db.exec_driver_sql(f"GRANT saas_metering TO {name} WITH INHERIT TRUE, SET FALSE")
        db.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {name}')
    try:
        engine = sa.create_engine(f.engine.url.set(username=name, password=password), pool_size=4)
        with engine.connect() as db:
            assert db.exec_driver_sql(
                "SELECT current_user=session_user,rolsuper,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).one() == (True, False, False)
            assert (
                db.exec_driver_sql(
                    "SELECT count(*) FROM saas_model_provider_budget_reservations"
                ).scalar_one()
                == 0
            )
            assert (
                db.exec_driver_sql("SELECT count(*) FROM saas_model_gateway_evidence").scalar_one()
                == 0
            )
            assert not db.scalar(
                sa.text(
                    "SELECT has_function_privilege(current_user,"
                    "'public.saas_gateway_customer_usage_guard_v1()','EXECUTE')"
                )
            )
        yield sessionmaker(engine, expire_on_commit=False)
    finally:
        if engine is not None:
            engine.dispose()
        with f.engine.begin() as db:
            db.exec_driver_sql(f"DROP OWNED BY {name}")
            db.exec_driver_sql(f"DROP ROLE {name}")


def _prepare(fixture, workers, authentication, billing, tmp_path, *, terminal=True, settle=True):
    f = fixture.base
    price = _customer_prices(
        f.factory, actor=fixture.runtime.actor_id, tenant=fixture.runtime.tenant_id
    )
    grant, lease, control, machine = _grant(fixture, workers, authentication)
    assert grant.customer_pricing_snapshot_id == price
    certificates, fingerprint = _register_metering_certificate(
        f.factory, machine["runner_id"], machine["connection_generation"], tmp_path
    )
    _enable_budget(f.factory)
    budgets = ModelProviderBudgetAdmissionService(billing)
    hold = _reserve(budgets, grant)
    budgets.begin_attempt(reservation_id=hold.id)
    usage = ModelTokenUsage(10, 0, 10, 3, 13)
    cost = grant.gateway_request(output_token_limit=32).model_price.cost(
        usage, at=datetime.now(timezone.utc)
    )
    if settle:
        budgets.resolve_attempt(
            reservation_id=hold.id,
            actual_microusd=cost,
            actual_tokens=13,
            evidence_sha256=None,
            gateway_usage=usage,
        )
    else:
        budgets.mark_uncertain(reservation_id=hold.id)
    if terminal:
        control.transition_run(
            **machine,
            run_id=lease.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            capability_token=lease.capability_token,
            target_status="succeeded",
        )
        control.release_run(**machine, run_id=lease.run_id, fence_token=lease.fence_token)
    return SimpleNamespace(
        f=f,
        grant=grant,
        lease=lease,
        machine=machine,
        price=price,
        certificates=certificates,
        fingerprint=fingerprint,
        hold=hold,
        budgets=budgets,
        usage=usage,
        cost=cost,
    )


@contextmanager
def _transport(prepared, metering, *, lose_first_ack=False):
    authority = BillingMeteringAuthority(metering)

    class Recorder:
        lost = False

        def record_usage(self, **kwargs):
            result = authority.record_usage(**kwargs)
            if lose_first_ack and not self.lost:
                self.lost = True
                raise RuntimeError("isolated committed-ack loss")
            return result

    server = MutualTlsBillingMeteringServer(
        Recorder(),
        _server_context(prepared.certificates["server"]),
        RunnerCertificateAuthority(metering, accepted_trust_bundle_versions=("test-v1",)),
    )
    thread = _ServerThread(server)
    thread.start()
    client = MutualTlsBillingMeteringClient(
        base_url=f"https://127.0.0.1:{server.port}",
        runner_id=prepared.machine["runner_id"],
        tls_context=_client_context(prepared.certificates["runner-0"]),
        timeout_seconds=10,
    )
    try:
        yield client
    finally:
        client.close()
        thread.close()


def _wire(p, meter="llm.input_tokens"):
    request = _request(p.f.factory, p.lease, p.fingerprint, p.hold, meter)
    request.pop("certificate_fingerprint_sha256")
    return request


def test_actual_login_and_mtls_record_late_gateway_usage_without_double_cost(
    interactive_postgresql, tmp_path
):
    f = interactive_postgresql.base
    with (
        _worker_logins(f) as workers,
        _authenticator_login(f) as authentication,
        _billing_login(f) as billing,
        _metering_login(f) as metering,
    ):
        p = _prepare(interactive_postgresql, workers, authentication, billing, tmp_path)
        _customer_prices(
            f.factory,
            actor=interactive_postgresql.runtime.actor_id,
            tenant=interactive_postgresql.runtime.tenant_id,
            rate=2500,
        )
        with f.factory() as db:
            cap = db.get(CapabilityTokenRecord, p.lease.capability_id)
            assert cap.revoked_at is not None and set(cap.allowed_actions) == {
                "run.execute",
                "runtime.interactive.execute",
            }
            expires = cap.expires_at
            before = db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd))
        sleep(max(0, (expires - datetime.now(timezone.utc)).total_seconds()) + 0.1)
        with f.engine.connect() as db:
            assert db.scalar(
                sa.text(
                    "SELECT expires_at<statement_timestamp() FROM saas_capability_tokens "
                    "WHERE id=:id"
                ),
                {"id": p.lease.capability_id},
            )
        with _transport(p, metering, lose_first_ack=True) as client:
            request = _wire(p)
            with pytest.raises(
                BillingMeteringTransportError, match="Billing Metering request failed"
            ):
                client.record_usage(**request)
            with ThreadPoolExecutor(max_workers=2) as pool:
                recovered = list(pool.map(lambda _: client.record_usage(**request), range(2)))
            assert recovered[0].receipt_id == recovered[1].receipt_id and all(
                row.replayed for row in recovered
            )
            output = client.record_usage(**_wire(p, "llm.output_tokens"))
            assert output.customer_charge_minor == 1 and output.pricing_snapshot_id == p.price
        with f.factory() as db:
            assert db.get(RunRecord, p.lease.run_id).status == "succeeded"
            assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 2
            assert (
                db.scalar(sa.select(sa.func.count()).select_from(BillingMeteringReceiptRecord))
                == 2
            )
            assert db.scalar(sa.select(sa.func.sum(UsageEventRecord.customer_charge_minor))) == 2
            assert (
                db.scalar(
                    sa.select(sa.func.count())
                    .select_from(ControlPlaneOutboxEvent)
                    .where(ControlPlaneOutboxEvent.event_type == "billing.usage.recorded")
                )
                == 2
            )
            assert (
                db.scalar(sa.select(ModelProviderMonthlyBudgetRecord.settled_microusd)) == before
            )
        with metering() as db:
            assert (
                db.execute(
                    sa.text("SELECT count(*) FROM saas_model_gateway_evidence")
                ).scalar_one()
                == 0
            )
        with (
            pytest.raises(RuntimeError, match=r"^retained execution schema cannot be downgraded$"),
            f.engine.begin() as db,
        ):
            config = Config(Path(__file__).resolve().parents[2] / "saas/control_plane/alembic.ini")
            config.attributes["connection"] = db
            command.downgrade(config, "lm2g00000001")


def test_database_guard_rolls_back_tampered_usage_receipt_and_outbox(
    interactive_postgresql, tmp_path
):
    f = interactive_postgresql.base
    with (
        _worker_logins(f) as workers,
        _authenticator_login(f) as authentication,
        _billing_login(f) as billing,
        _metering_login(f) as metering,
    ):
        p = _prepare(
            interactive_postgresql, workers, authentication, billing, tmp_path, terminal=False
        )
        authority = BillingMeteringAuthority(metering)
        request = _request(f.factory, p.lease, p.fingerprint, p.hold)
        engine = metering.kw["bind"]
        for table, field, value in (
            ("saas_usage_events", "quantity", 11),
            ("saas_usage_events", "customer_charge_minor", 999),
            ("saas_billing_metering_receipts", "request_hash", "e" * 64),
            ("saas_control_plane_outbox", "request_hash", "e" * 64),
        ):

            def corrupt(
                _connection,
                _cursor,
                statement,
                parameters,
                _context,
                _executemany,
                target=table,
                column=field,
                replacement=value,
            ):
                if statement.startswith("INSERT INTO " + target):
                    parameters = {**parameters, column: replacement}
                return statement, parameters

            sa.event.listen(engine, "before_cursor_execute", corrupt, retval=True)
            try:
                with pytest.raises(sa.exc.DBAPIError) as denied:
                    authority.record_usage(**request)
                assert denied.value.orig.sqlstate == "23514"
            finally:
                sa.event.remove(engine, "before_cursor_execute", corrupt)
            with f.factory() as db:
                assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
                assert (
                    db.scalar(sa.select(sa.func.count()).select_from(BillingMeteringReceiptRecord))
                    == 0
                )
        with pytest.raises(sa.exc.DBAPIError, match="requires machine metering"):
            BillingControlPlane(billing).record_usage(
                actor_id=interactive_postgresql.runtime.actor_id,
                tenant_id=p.grant.claims.tenant_id,
                pricing_snapshot_id=p.price,
                meter="llm.input_tokens",
                quantity=10,
                unit="tokens",
                provider="deepseek",
                provider_request_id="manual-owner-cannot-charge",
                idempotency_key="manual-owner-cannot-charge",
                occurred_at=request["occurred_at"],
                space_id=p.grant.claims.space_id,
                project_id=p.grant.claims.project_id,
                run_id=p.lease.run_id,
                session_id=p.grant.execution_session_id,
                user_id=p.grant.claims.actor_id,
            )
        assert authority.record_usage(**request).customer_charge_minor == 1


def test_unknown_outcome_and_revoked_real_certificate_never_charge(
    interactive_postgresql, tmp_path
):
    f = interactive_postgresql.base
    with (
        _worker_logins(f) as workers,
        _authenticator_login(f) as authentication,
        _billing_login(f) as billing,
        _metering_login(f) as metering,
    ):
        p = _prepare(
            interactive_postgresql,
            workers,
            authentication,
            billing,
            tmp_path,
            terminal=False,
            settle=False,
        )
        with _transport(p, metering) as client:
            request = {
                "runner_id": p.machine["runner_id"],
                "run_id": p.lease.run_id,
                "capability_token": p.lease.capability_token,
                "meter": "llm.input_tokens",
                "quantity": "10",
                "unit": "tokens",
                "provider": "deepseek",
                "provider_request_id": f"model-gateway:{p.hold.id}",
                "idempotency_key": f"model-gateway:{p.hold.id}:input",
                "occurred_at": datetime.now(timezone.utc),
                "model_budget_reservation_id": p.hold.id,
            }
            with pytest.raises(BillingMeteringTransportError) as unknown:
                client.record_usage(**request)
            assert unknown.value.code == "metering_gateway_evidence_denied"
            p.budgets.resolve_attempt(
                reservation_id=p.hold.id,
                actual_microusd=p.cost,
                actual_tokens=13,
                evidence_sha256=None,
                gateway_usage=p.usage,
            )
            RunnerCertificateAuthority(
                f.factory, accepted_trust_bundle_versions=("test-v1",)
            ).revoke_certificate(fingerprint_sha256=p.fingerprint, reason="isolated revoke")
            with pytest.raises(BillingMeteringTransportError) as revoked:
                client.record_usage(**_wire(p))
            assert revoked.value.code == "billing_metering_runner_certificate_denied"
        with f.factory() as db:
            assert db.scalar(sa.select(sa.func.count()).select_from(UsageEventRecord)) == 0
