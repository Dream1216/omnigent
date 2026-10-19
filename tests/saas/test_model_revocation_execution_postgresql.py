from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from saas.control_plane import model_revocations
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunRecord
from saas.control_plane.model_budget import ModelProviderBudgetAdmissionService
from saas.control_plane.model_publications import ModelPublicationService
from saas.control_plane.model_revocation_execution import ModelRevocationRunCanceller
from saas.control_plane.platform_models import ModelProviderConfigurationRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
)
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from saas.production import platform_model_gateway as gateway_module
from saas.production.model_run_inference import LiteLLMRunInference
from saas.production.platform_model_gateway import PlatformModelGateway
from tests.saas import test_tenant_model_catalog_postgresql as tenant_fixture
from tests.saas.test_interactive_dispatch_postgresql import _worker_logins
from tests.saas.test_interactive_execution_postgresql import (
    interactive_postgresql as interactive_postgresql,
)
from tests.saas.test_model_run_cancellation import _request, _settings, _state
from tests.saas.test_model_run_evidence import _enable_budget
from tests.saas.test_model_run_evidence_postgresql import _billing_login
from tests.saas.test_model_run_evidence_postgresql import (
    publication_protocol as publication_protocol,
)
from tests.saas.test_model_run_inference import _stream
from tests.saas.test_model_run_inference_postgresql import _run_binding
from tests.saas.test_model_run_inference_postgresql import (
    funded_publication as funded_publication,
)
from tests.saas.test_run_customer_pricing_postgresql import priced_execution as priced_execution


@pytest.fixture(autouse=True)
def publication_source(funded_publication, monkeypatch):
    original, captured = tenant_fixture._fixture, {}

    def capture():
        result = original()
        captured["source"], captured["actor"] = result[0], result[3]
        return result

    monkeypatch.setattr(tenant_fixture, "_fixture", capture)
    return captured


@contextmanager
def _staff(f, source):
    login = "security_staff_" + uuid4().hex[:16]
    password, engine, created = "isolated-security-staff-only", None, False
    try:
        with f.engine.begin() as db:
            db.exec_driver_sql(
                f"CREATE ROLE {login} LOGIN PASSWORD '{password}' "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT"
            )
            created = True
            db.exec_driver_sql(f"GRANT saas_platform_app TO {login} WITH INHERIT TRUE, SET FALSE")
            db.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{f.engine.url.database}" TO {login}')
        engine = sa.create_engine(f.engine.url.set(username=login, password=password))
        yield (
            ModelPublicationService(
                engine,
                authorization=PlatformAuthorizationService(sessionmaker(engine)),
                pricing=source._pricing,
            ),
            engine,
        )
    finally:
        if engine is not None:
            engine.dispose()
        if created:
            with f.engine.begin() as db:
                db.exec_driver_sql(f"DROP OWNED BY {login}")
                db.exec_driver_sql(f"DROP ROLE {login}")


def _terminal(workers, binding):
    return SchedulingControlPlane(workers["executor"]).authenticated_run_transition(
        ExecutionControlPlane(workers["executor"]),
        **binding.machine,
        run_id=binding.lease.run_id,
        lease_token=binding.lease.lease_token,
        fence_token=binding.lease.fence_token,
        capability_token=binding.lease.capability_token,
        target_status="succeeded",
        trace_id="isolated-pg-terminal-race",
    )


@pytest.mark.parametrize("first", ("staff", "terminal"))
def test_actual_roles_serialize_revocation_admission_with_terminal_transition(
    interactive_postgresql, publication_source, monkeypatch, first
):
    f = interactive_postgresql.base
    with (
        _run_binding(interactive_postgresql, None) as binding,
        _worker_logins(f) as workers,
        _staff(f, publication_source["source"]) as (staff, staff_engine),
    ):
        actor = publication_source["actor"]
        publication = staff.list(actor)[0]
        cutoff = staff.disable(
            actor,
            publication_id=publication.id,
            expected_generation=1,
            idempotency_key="serialize-cutoff-real-001",
        )
        selected = {
            "staff": staff_engine.url.username,
            "terminal": workers["executor"].kw["bind"].url.username,
        }
        entered, release = threading.Event(), threading.Event()
        lock = model_revocations.lock_model_security_scope

        def held(db, **scope):
            lock(db, **scope)
            if db.get_bind().url.username == selected[first]:
                entered.set()
                assert release.wait(10), "controlled scope-lock holder was not released"

        monkeypatch.setattr(model_revocations, "lock_model_security_scope", held)

        def revoke():
            return staff.security_revocations.request(
                actor,
                disablement_id=cutoff["disablement_id"],
                expected_generation=1,
                idempotency_key="serialize-revoke-real-001",
            )

        calls = {"staff": revoke, "terminal": lambda: _terminal(workers, binding)}
        other = "terminal" if first == "staff" else "staff"
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(calls[first])
            try:
                assert entered.wait(10)
                b = pool.submit(calls[other])
                blocked, deadline = False, time.monotonic() + 10
                while time.monotonic() < deadline:
                    with f.engine.connect() as db:
                        blocked = db.scalar(
                            sa.text(
                                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity "
                                "WHERE usename=:role AND wait_event='advisory')"
                            ),
                            {"role": selected[other]},
                        )
                    if blocked:
                        break
                    assert not b.done(), "second transaction skipped the shared scope lock"
                    time.sleep(0.01)
                assert blocked
            finally:
                release.set()
            results = {first: a.result(20), other: b.result(20)}
        assert results["terminal"].status == ("cancelling" if first == "staff" else "succeeded")
        with f.factory() as db:
            run = db.get(RunRecord, binding.lease.run_id)
            assert run.status == results["terminal"].status
            if first == "terminal":
                assert run.terminal_at < results["staff"]["created_at"]
            else:
                assert (
                    db.get(CapabilityTokenRecord, binding.lease.capability_id).revoked_at is None
                )


def test_locked_run_is_deferred_without_losing_its_retained_security_intent(
    interactive_postgresql, publication_source
):
    f = interactive_postgresql.base
    with (
        _run_binding(interactive_postgresql, None) as binding,
        _worker_logins(f) as workers,
        _staff(f, publication_source["source"]) as (staff, _),
    ):
        actor = publication_source["actor"]
        publication = staff.list(actor)[0]
        cutoff = staff.disable(
            actor,
            publication_id=publication.id,
            expected_generation=publication.generation,
            idempotency_key="locked-run-cutoff-001",
        )
        intent = staff.security_revocations.request(
            actor,
            disablement_id=cutoff["disablement_id"],
            expected_generation=publication.generation,
            idempotency_key="locked-run-revocation-001",
        )
        canceller = ModelRevocationRunCanceller(workers["executor"])
        with workers["executor"].begin() as locked:
            assert (
                locked.scalar(
                    sa.select(RunRecord.id)
                    .where(RunRecord.id == binding.lease.run_id)
                    .with_for_update()
                )
                == binding.lease.run_id
            )
            assert canceller.cancel_pending() == ()
            with f.factory() as db:
                assert db.get(RunRecord, binding.lease.run_id).status == "running"
        changed = canceller.cancel_pending()
        assert len(changed) == 1 and changed[0].run_id == binding.lease.run_id
        assert changed[0].status == "cancelling" and canceller.cancel_pending() == ()
        from saas.control_plane.execution_models import RunEventRecord

        with f.factory() as db:
            event = db.scalars(
                sa.select(RunEventRecord).where(
                    RunEventRecord.run_id == binding.lease.run_id,
                    RunEventRecord.event_type == "run.cancelling",
                )
            ).one()
            assert event.payload["model_revocation_id"] == str(intent["revocation_id"])
            assert db.get(CapabilityTokenRecord, binding.lease.capability_id).revoked_at is None


@pytest.mark.parametrize("phase", ("staff", "terminal"))
def test_non_read_committed_scope_cannot_retain_intent_or_publish_terminal_result(
    interactive_postgresql, publication_source, phase
):
    f = interactive_postgresql.base
    with (
        _run_binding(interactive_postgresql, None) as binding,
        _worker_logins(f) as workers,
        _staff(f, publication_source["source"]) as (staff, staff_engine),
    ):
        actor = publication_source["actor"]
        publication = staff.list(actor)[0]
        cutoff = staff.disable(
            actor,
            publication_id=publication.id,
            expected_generation=1,
            idempotency_key="isolation-cutoff-real-001",
        )
        with pytest.raises(PlatformSecurityError) as denied:
            if phase == "staff":
                isolated = staff_engine.execution_options(isolation_level="REPEATABLE READ")
                rejected = ModelPublicationService(
                    isolated,
                    authorization=PlatformAuthorizationService(sessionmaker(isolated)),
                    pricing=publication_source["source"]._pricing,
                )
                rejected.security_revocations.request(
                    actor,
                    disablement_id=cutoff["disablement_id"],
                    expected_generation=1,
                    idempotency_key="isolation-revoke-real-001",
                )
            else:
                staff.security_revocations.request(
                    actor,
                    disablement_id=cutoff["disablement_id"],
                    expected_generation=1,
                    idempotency_key="isolation-revoke-real-001",
                )
                isolated = (
                    workers["executor"]
                    .kw["bind"]
                    .execution_options(isolation_level="REPEATABLE READ")
                )
                _terminal({"executor": sessionmaker(isolated)}, binding)
        assert denied.value.code == "platform_model_revocation_isolation_unavailable"
        with f.factory() as db:
            assert db.get(RunRecord, binding.lease.run_id).status == "running"


@pytest.mark.parametrize("phase", ("headers", "unknown-body", "known-body"))
def test_actual_staff_intent_stops_app_gateway_and_executor_requests_physical_cancel(
    interactive_postgresql, publication_source, monkeypatch, phase
):
    _settings(monkeypatch)
    monkeypatch.setattr(gateway_module, "_RUN_AUTHORITY_TIMEOUT_SECONDS", 5.0)
    f = interactive_postgresql.base
    with (
        _run_binding(interactive_postgresql, None) as binding,
        _billing_login(f) as billing,
        _worker_logins(f) as workers,
        _staff(f, publication_source["source"]) as (staff, engine),
    ):
        credentials, lease = binding.credentials, binding.lease
        issued = credentials.issue(binding.authorized, lease)
        published = credentials.authorize(credentials.authenticate(issued.value))
        actor = publication_source["actor"]
        publication = staff.list(actor)[0]
        _enable_budget(f.factory)
        with f.factory.begin() as db:
            config = db.get(ModelProviderConfigurationRecord, "deepseek")
            config.monthly_budget_microusd, config.per_tenant_daily_token_limit = (
                1_000_000,
                100_000,
            )
        responses, known, calls, closed = (
            published.configuration["wire_api"] == "openai_responses",
            phase == "known-body",
            [],
            [],
        )

        def revoke():
            cutoff = staff.disable(
                actor,
                publication_id=publication.id,
                expected_generation=1,
                idempotency_key="security-cutoff-real-001",
            )
            result = staff.security_revocations.request(
                actor,
                disablement_id=cutoff["disablement_id"],
                expected_generation=1,
                idempotency_key="security-revoke-real-001",
            )
            assert result["revocation_requested"] and not result["execution_complete"]
            with f.factory() as db:
                assert db.get(RunRecord, lease.run_id).status == "running"
                assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is None

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield _stream(responses) if known else b'data: {"choices":[]}\n\n'
                await asyncio.to_thread(revoke)
                await asyncio.Event().wait()

            async def aclose(self):
                closed.append(True)

        async def upstream(request):
            calls.append(request)
            if phase != "headers":
                return httpx.Response(200, stream=Body())
            try:
                await asyncio.to_thread(revoke)
                await asyncio.Event().wait()
            finally:
                closed.append(True)

        gateway = PlatformModelGateway(
            tokens=None,
            configurations=None,
            pricing=None,
            budgets=ModelProviderBudgetAdmissionService(billing),
            run_credentials=credentials,
            run_inference=LiteLLMRunInference(
                "https://litellm.test",
                "isolated-inference-only-not-a-real-key",
                (published.configuration["deployment_alias"],),
                billing,
            ),
            client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
        )
        p = SimpleNamespace(
            f=f, lease=lease, grant=published, issued=issued, responses=responses, gateway=gateway
        )
        call = uuid4()
        result = asyncio.run(_request(p, call, timeout=10))
        assert result.status_code == (403 if phase == "headers" else 200), result.text
        assert len(calls) == 1 and closed
        assert _state(p, call) == (("settled", 13, 0) if known else ("uncertain", 0, 0))
        canceller = ModelRevocationRunCanceller(workers["executor"])
        changed = canceller.cancel_pending()
        assert len(changed) == 1 and changed[0].run_id == lease.run_id
        assert changed[0].status == "cancelling" and canceller.cancel_pending() == ()
        with f.factory() as db:
            assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is None
        with pytest.raises(sa.exc.DBAPIError), engine.connect() as db:
            db.exec_driver_sql("SELECT * FROM public.saas_runs")
        with pytest.raises(sa.exc.DBAPIError), workers["executor"].begin() as db:
            db.execute(
                sa.text("SELECT staff_session_id FROM public.saas_model_publication_revocations")
            )
