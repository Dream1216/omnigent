from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.execution import ExecutionControlPlane, ExecutionControlPlaneError
from saas.control_plane.execution_models import RunEventRecord, RunRecord
from saas.control_plane.model_revocation_execution import ModelRevocationRunCanceller
from saas.control_plane.model_revocations import run_security_revoked
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.scheduling_models import CapabilityTokenRecord
from tests.saas.test_interactive_execution_http import _message, _post
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_model_disablement_runtime import _disable
from tests.saas.test_model_run_cancellation import _request, _settings, _state
from tests.saas.test_model_run_inference import _setup, _stream

pytestmark = pytest.mark.parametrize("interactive_http", (False, True), indirect=True)


def _revoke(f, cutoff):
    return f.publication_service.security_revocations.request(
        f.publication_actor,
        disablement_id=cutoff["disablement_id"],
        expected_generation=cutoff["through_generation"],
        idempotency_key="security-runtime-001",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ("headers", "unknown-body", "known-body"))
async def test_security_intent_stops_accepted_io_before_worker_cancel_without_zeroing_unknown_cost(
    interactive_http, tmp_path, monkeypatch, phase
):
    _settings(monkeypatch)
    p = await _setup(interactive_http, tmp_path)
    closed = asyncio.Event()
    known = phase == "known-body"

    def revoke():
        _revoke(p.f, _disable(p.f))
        with p.f.factory() as db:
            assert db.get(RunRecord, p.lease.run_id).status == "running"
            assert db.get(CapabilityTokenRecord, p.lease.capability_id).revoked_at is None

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield _stream(p.responses) if known else b'data: {"choices":[]}\n\n'
            revoke()
            await asyncio.Event().wait()

        async def aclose(self):
            closed.set()

    async def upstream(request):
        p.calls.append(request)
        if phase != "headers":
            return httpx.Response(200, stream=Body())
        revoke()
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    p.gateway._client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    call = uuid4()
    result = await _request(p, call)
    assert result.status_code == (403 if phase == "headers" else 200)
    assert closed.is_set() and len(p.calls) == 1
    assert _state(p, call) == (("settled", 13, 0) if known else ("uncertain", 0, 0))
    assert (await _request(p, uuid4())).status_code == 403 and len(p.calls) == 1


@pytest.mark.asyncio
async def test_executor_applies_bounded_idempotent_cancellation_and_preserves_stop_authority(
    interactive_http, tmp_path
):
    p = await _setup(interactive_http, tmp_path)
    queued = _post(p.f, _message(uuid4().hex))
    assert queued.status_code == 202
    canceller = ModelRevocationRunCanceller(p.f.factory)
    cutoff = _disable(p.f)
    assert canceller.cancel_pending() == ()
    receipt = _revoke(p.f, cutoff)
    with p.f.factory() as db:
        assert run_security_revoked(db, p.lease.run_id)
    first, second = canceller.cancel_pending(limit=1), canceller.cancel_pending(limit=1)
    assert len(first) == len(second) == 1 and first[0].run_id != second[0].run_id
    assert canceller.cancel_pending() == ()
    with p.f.factory() as db:
        assert db.get(RunRecord, p.lease.run_id).status == "cancelling"
        assert db.get(RunRecord, UUID(queued.json()["run_id"])).status == "cancelled"
        assert db.get(CapabilityTokenRecord, p.lease.capability_id).revoked_at is None
        events = list(
            db.scalars(
                sa.select(RunEventRecord).where(
                    RunEventRecord.event_type.in_(("run.cancelled", "run.cancelling"))
                )
            )
        )
        assert len(events) == 2
        assert all(
            e.payload["model_revocation_id"] == str(receipt["revocation_id"]) for e in events
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ("succeeded", "failed", "timed_out"))
@pytest.mark.parametrize("security", (False, True))
async def test_model_terminal_transition_observes_security_intent_without_waiting_for_poll(
    interactive_http, tmp_path, target, security
):
    p = await _setup(interactive_http, tmp_path)
    cutoff = _disable(p.f)
    receipt = _revoke(p.f, cutoff) if security else None
    c, lease = p.connection, p.lease
    result = SchedulingControlPlane(p.f.factory).authenticated_run_transition(
        ExecutionControlPlane(p.f.factory),
        runner_id=c.runner_id,
        connection_generation=c.connection_generation,
        connection_token=c.connection_token,
        run_id=lease.run_id,
        lease_token=lease.lease_token,
        fence_token=lease.fence_token,
        capability_token=lease.capability_token,
        target_status=target,
        trace_id="isolated-model-terminal-race",
    )
    assert result.status == ("cancelling" if security else target)
    with p.f.factory() as db:
        assert db.get(RunRecord, lease.run_id).status == result.status
        if security:
            assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is None
            event = db.scalars(
                sa.select(RunEventRecord).where(
                    RunEventRecord.run_id == lease.run_id,
                    RunEventRecord.event_type == "run.cancelling",
                )
            ).one()
            assert event.payload["model_revocation_id"] == str(receipt["revocation_id"])
    assert ModelRevocationRunCanceller(p.f.factory).cancel_pending() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ("lease_token", "fence_token"))
async def test_terminal_security_check_cannot_mutate_with_an_invalid_lease(
    interactive_http, tmp_path, changed
):
    p = await _setup(interactive_http, tmp_path)
    _revoke(p.f, _disable(p.f))
    c, lease = p.connection, p.lease
    fields = {"lease_token": lease.lease_token, "fence_token": lease.fence_token}
    fields[changed] = uuid4() if changed == "lease_token" else lease.fence_token + 1
    with pytest.raises(ExecutionControlPlaneError):
        SchedulingControlPlane(p.f.factory).authenticated_run_transition(
            ExecutionControlPlane(p.f.factory),
            runner_id=c.runner_id,
            connection_generation=c.connection_generation,
            connection_token=c.connection_token,
            run_id=lease.run_id,
            capability_token=lease.capability_token,
            target_status="succeeded",
            trace_id="isolated-invalid-terminal-lease",
            **fields,
        )
    with p.f.factory() as db:
        assert db.get(RunRecord, lease.run_id).status == "running"
