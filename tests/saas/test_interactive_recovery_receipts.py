from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from saas.control_plane.db_models import ControlPlaneOutboxEvent
from saas.control_plane.execution import ExecutionControlPlane
from saas.control_plane.execution_models import RunEventRecord, RunRecord, TaskRecord
from saas.control_plane.scheduling import SchedulingError
from saas.control_plane.scheduling_models import (
    CapabilityTokenRecord,
    RunDispatchRecord,
    RunnerPoolRecord,
    RunnerRegistrationRecord,
)
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    MutualTlsRunnerControlServer,
    ProductionRunnerMachineAuthority,
    RunnerControlError,
)
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_runner_lease import _admit, _claim, _controller, _register
from tests.saas.test_production_runner_control import (
    _CertificateAuthorizer,
    _certificates,
    _client_context,
    _server_context,
)


@pytest.fixture
def recovery_case(interactive_http):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    old = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="recovery-controller")
    now = datetime.now(timezone.utc)
    lease = _claim(scheduling, connection, now=now)
    later = now + timedelta(seconds=6)
    assert scheduling.recover_expired_dispatches(now=later) == (old,)
    queued = _admit(f, "b" * 32, text="New input after physical recovery")
    assert _claim(scheduling, connection, now=later) is None
    return f, scheduling, connection, lease, queued, later


def _confirmation(connection, lease, later):
    return {
        "runner_id": connection.runner_id,
        "connection_generation": connection.connection_generation,
        "connection_token": connection.connection_token,
        "run_id": lease.run_id,
        "fence_token": lease.fence_token,
        "capability_token": lease.capability_token,
        "proof_sha256": "b" * 64,
        "certificate_fingerprint_sha256": "a" * 64,
        "expected_product_revision": "c" * 40,
        "product_image_digest": "sha256:" + "a" * 64,
        "now": later,
    }


def test_exact_recovery_receipt_unblocks_only_new_input_and_replays_once(recovery_case):
    f, scheduling, connection, lease, queued, later = recovery_case
    with f.factory() as db:
        events_before = db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord))
        outbox_before = db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent))
    values = _confirmation(connection, lease, later)
    assert scheduling.confirm_interactive_recovery(**values) is False
    assert scheduling.confirm_interactive_recovery(**values) is True
    with f.factory() as db:
        assert db.get(RunRecord, lease.run_id).status == "orphaned"
        assert db.get(RunDispatchRecord, lease.run_id).physical_recovery_fence == lease.fence_token
        assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is not None
        assert db.scalar(sa.select(sa.func.count()).select_from(TaskRecord)) == 2
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == events_before + 1
        )
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(ControlPlaneOutboxEvent))
            == outbox_before + 1
        )
        receipt = db.scalars(
            sa.select(RunEventRecord).where(
                RunEventRecord.run_id == lease.run_id,
                RunEventRecord.event_type == "run.interactive_physical_recovered",
            )
        ).one()
        assert receipt.payload["proof_sha256"] == "b" * 64
        assert receipt.payload["certificate_fingerprint_sha256"] == "a" * 64
        assert connection.connection_token not in str(receipt.payload)
        assert lease.capability_token not in str(receipt.payload)
    fresh = _claim(scheduling, connection, now=later)
    assert fresh is not None and fresh.run_id == queued and fresh.run_id != lease.run_id


def test_generic_run_event_cannot_forge_a_physical_recovery_receipt(recovery_case):
    f, scheduling, connection, lease, _, later = recovery_case
    with f.factory.begin() as db:
        run = db.get(RunRecord, lease.run_id)
        ExecutionControlPlane._append_event(
            db,
            run,
            event_type="run.interactive_physical_recovered",
            payload={"fence_token": lease.fence_token, "proof_sha256": "b" * 64},
            trace_id="isolated-untrusted-app-event",
        )
    assert _claim(scheduling, connection, now=later) is None
    with f.factory() as db:
        assert db.get(RunDispatchRecord, lease.run_id).physical_recovery_fence is None


@pytest.mark.parametrize("terminal", ("succeeded", "failed", "cancelled", "timed_out"))
def test_stopped_terminal_run_receipt_keeps_outcome_and_revoked_authority(
    interactive_http, terminal
):
    f = interactive_http
    scheduling, pool, domain, schema = _controller(f)
    run_id = _admit(f)
    connection = _register(f, scheduling, pool, domain, schema, key="terminal-stop-controller")
    now = datetime.now(timezone.utc)
    lease = _claim(scheduling, connection, now=now)
    execution = ExecutionControlPlane(f.factory)
    for status in (
        "starting",
        "running",
        *(("cancelling",) if terminal == "cancelled" else ()),
        terminal,
    ):
        execution.transition_run(
            run_id=run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            target_status=status,
            trace_id="isolated-terminal-stop",
            now=now,
        )
    values = _confirmation(connection, lease, now)
    with pytest.raises(SchedulingError, match="pending"):
        scheduling.confirm_interactive_recovery(**values)
    scheduling.release_dispatch(
        run_id=run_id,
        runner_id=connection.runner_id,
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
        fence_token=lease.fence_token,
        requeue=False,
        now=now,
    )
    assert scheduling.confirm_interactive_recovery(**values) is False
    assert scheduling.confirm_interactive_recovery(**values) is True
    with f.factory() as db:
        run, dispatch = db.get(RunRecord, run_id), db.get(RunDispatchRecord, run_id)
        assert run.status == terminal and dispatch.status == "released"
        assert dispatch.physical_recovery_fence == lease.fence_token
        assert db.get(CapabilityTokenRecord, lease.capability_id).revoked_at is not None
        assert db.get(RunnerRegistrationRecord, connection.runner_id).active_leases == 0
        events = db.scalars(
            sa.select(RunEventRecord).where(
                RunEventRecord.run_id == run_id,
                RunEventRecord.event_type == "run.interactive_physical_recovered",
            )
        ).all()
        assert len(events) == 1 and events[0].payload["proof_sha256"] == "b" * 64


def test_foreign_registered_machine_cannot_confirm_the_original_recovery(recovery_case):
    f, scheduling, original, lease, _, later = recovery_case
    with f.factory() as db:
        registered = db.get(RunnerRegistrationRecord, original.runner_id)
        pool = db.get(RunnerPoolRecord, registered.pool_id)
        pool_id, domain, schema = pool.id, registered.failure_domain, pool.schema_revision
    foreign = _register(f, scheduling, pool_id, domain, schema, key="foreign-recovery-controller")
    with pytest.raises(SchedulingError):
        scheduling.confirm_interactive_recovery(**_confirmation(foreign, lease, later))


@pytest.mark.parametrize(
    "changed",
    [
        "fence_token",
        "connection_generation",
        "connection_token",
        "capability_token",
        "proof_sha256",
        "certificate_fingerprint_sha256",
        "expected_product_revision",
        "product_image_digest",
    ],
)
def test_recovery_acknowledgement_rejects_stale_or_unbound_authority(recovery_case, changed):
    f, scheduling, connection, lease, _, later = recovery_case
    values = _confirmation(connection, lease, later)
    values[changed] = (
        values[changed] + 1 if changed in {"fence_token", "connection_generation"} else "invalid"
    )
    with pytest.raises(SchedulingError):
        scheduling.confirm_interactive_recovery(**values)
    with f.factory() as db:
        assert db.get(RunDispatchRecord, lease.run_id).physical_recovery_fence is None
        assert not db.scalar(
            sa.select(sa.func.count())
            .select_from(RunEventRecord)
            .where(RunEventRecord.event_type == "run.interactive_physical_recovered")
        )
    assert _claim(scheduling, connection, now=later) is None


@pytest.mark.asyncio
async def test_mtls_recovery_derives_its_certificate_and_never_accepts_a_client_fingerprint(
    recovery_case,
    tmp_path,
):
    f, scheduling, connection, lease, _, _ = recovery_case
    certificates = _certificates(tmp_path, runner_id=connection.runner_id)

    class CommitThenError(ProductionRunnerMachineAuthority):
        acknowledged = False

        def confirm_interactive_recovery(self, **values):
            replayed = super().confirm_interactive_recovery(**values)
            if not self.acknowledged:
                self.acknowledged = True
                raise RunnerControlError("isolated_receipt_ack_error", "Isolated acknowledgement")
            return replayed

    server = MutualTlsRunnerControlServer(
        CommitThenError(
            scheduling,
            ExecutionControlPlane(f.factory),
            product_revision="c" * 40,
            image_digest="sha256:" + "a" * 64,
        ),
        _server_context(certificates["server"]),
        _CertificateAuthorizer(),
    )
    await server.start()
    client = MutualTlsRunnerControlClient(
        connect_host="localhost",
        port=server.port,
        server_name="localhost",
        tls_context=_client_context(certificates["runner"]),
        connection_generation=connection.connection_generation,
        connection_token=connection.connection_token,
    )
    fields = {
        "run_id": str(lease.run_id),
        "fence_token": lease.fence_token,
        "capability_token": lease.capability_token,
        "proof_sha256": "b" * 64,
    }
    try:
        with pytest.raises(RunnerControlError) as denied:
            await client._request(
                "confirm_interactive_recovery",
                {
                    **fields,
                    "certificate_fingerprint_sha256": "0" * 64,
                },
            )
        assert denied.value.code == "runner_control_request_invalid"
        with pytest.raises(RunnerControlError) as lost_ack:
            await client.confirm_interactive_recovery(**{**fields, "run_id": lease.run_id})
        assert lost_ack.value.code == "isolated_receipt_ack_error"
        assert await client.confirm_interactive_recovery(**{**fields, "run_id": lease.run_id})
    finally:
        await server.aclose()
    fingerprint = sha256(
        x509.load_pem_x509_certificate(
            certificates["runner"].certificate.read_bytes()
        ).public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    with f.factory() as db:
        event = db.scalars(
            sa.select(RunEventRecord).where(
                RunEventRecord.event_type == "run.interactive_physical_recovered"
            )
        ).one()
        assert event.payload["certificate_fingerprint_sha256"] == fingerprint
