from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from saas.control_plane import QuotaReservationRecord, RunEventRecord, RunRecord
from saas.observability import SloMetrics, SloRuntime, install_session_witness, runtime_scope
from saas.production.slo_witness import (
    RunEventWitness,
    StoredObject,
    WitnessBackfillRequired,
    WitnessConflict,
    WitnessUnavailable,
)
from tests.saas.test_execution_control_plane import _revisions
from tests.saas.test_execution_control_plane import (
    execution_control_plane as execution_control_plane,
)
from tests.saas.test_run_dispatch_projection import (
    runtime_dispatch_fixture as runtime_dispatch_fixture,
)
from tests.saas.test_worktree_control_plane import worktree_fixture as worktree_fixture


class _Store:
    """Explicit per-test independent store; never a production qualification."""

    def __init__(self):
        self.objects = {}
        self.fail = False
        self.revisions = 0

    def read(self, key):
        return self.objects.get(key)

    def first(self, prefix):
        keys = sorted(key for key in self.objects if key.startswith(prefix))
        return (keys[0], self.objects[keys[0]]) if keys else None

    def conditional_put(self, key, body, *, expected_etag):
        if self.fail:
            raise WitnessUnavailable("injected independent storage failure")
        previous = self.objects.get(key)
        if (None if previous is None else previous.etag) != expected_etag:
            raise WitnessConflict("conditional store conflict")
        self.revisions += 1
        result = StoredObject(body, hashlib.sha256(body).hexdigest(), str(self.revisions))
        self.objects[key] = result
        return result


def _runtime(factory):
    store = _Store()
    runtime = SloRuntime(
        SloMetrics(),
        RunEventWitness(store, product_revision="a" * 40, key_version="v1", hmac_key=b"x" * 32),
    )
    install_session_witness(factory, runtime)
    return runtime, store


def _metric_sample(metrics, name):
    return float(
        next(line[len(name) + 1 :] for line in metrics.splitlines() if line.startswith(name + " "))
    )


def test_fixed_initial_series_capture_first_real_http_failure_and_slow_stage(monkeypatch):
    from saas.observability import SloHttpMiddleware, measure_stage

    metrics = SloMetrics()
    initial = metrics.render().decode()
    counter = 'saas_slo_operations_total{operation="auth_eligible",outcome="failure"}'
    count = (
        'saas_slo_stage_duration_seconds_count{stage="outbox_audit_delivery",outcome="success"}'
    )
    bucket = (
        'saas_slo_stage_duration_seconds_bucket{stage="outbox_audit_delivery",'
        'outcome="success",le="60"}'
    )
    assert counter + " 0" in initial and count + " 0" in initial and bucket + " 0" in initial
    assert (
        sum(line.startswith("saas_slo_operations_total{") for line in initial.splitlines()) == 78
    )
    assert (
        sum(line.startswith("saas_slo_stage_duration_seconds_") for line in initial.splitlines())
        == 1440
    )
    assert (
        "saas_slo_postgresql_pool_observed_count 0" in initial
    )  # Explicitly unobserved, not healthy.
    now = [100.0]
    monkeypatch.setattr("saas.observability.time.monotonic", lambda: now[0])
    runtime = SloRuntime(metrics, None)

    async def dependency_failed(scope, receive, send):
        now[0] += 61
        await send({"type": "http.response.start", "status": 503, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def request():
        messages = []

        async def send(message):
            messages.append(message)

        await SloHttpMiddleware(dependency_failed)(
            {"type": "http", "path": "/v1/measured", "method": "GET", "state": {}}, None, send
        )
        assert messages[0]["status"] == 503

    @measure_stage("outbox_audit_delivery")
    def actual_instrument_callback():
        now[0] += 61

    with runtime_scope(runtime):
        asyncio.run(request())
        actual_instrument_callback()
    after = metrics.render().decode()
    assert counter + " 1" in after and count + " 1" in after and bucket + " 0" in after
    assert (
        'saas_slo_stage_duration_seconds_bucket{stage="outbox_audit_delivery",'
        'outcome="success",le="+Inf"} 1' in after
    )
    assert (
        'saas_slo_stage_duration_seconds_count{stage="auth_session",outcome="failure"} 1' in after
    )
    assert after.count("\n") == initial.count(
        "\n"
    )  # First calls never create a new metric series.


def _admit(service, scope, request):
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=3
    )
    task = service.create_task(request, project_id=scope.project_id, title="Commit boundary")
    return lambda: service.admit_run(
        request,
        project_id=scope.project_id,
        task_id=task,
        session_id=None,
        input_payload={"prompt": "private customer text"},
        quota_resource="run_units",
        quota_units=1,
        idempotency_key="exact-retry",
        revisions=_revisions(),
    )


def test_witness_failure_after_real_commit_blocks_ack_and_idempotent_retry_recovers(
    execution_control_plane,
):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, store = _runtime(factory)
    store.fail = True
    with runtime_scope(runtime), pytest.raises(WitnessUnavailable):
        admit()
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 1
    store.fail = False
    with runtime_scope(runtime):
        replay = admit()
    assert replay.replayed is True
    head, _ = runtime.witness.checkpoint(str(scope.tenant_id), str(replay.run_id))
    assert head["sequence"] == 2
    assert b"private customer text" not in b"".join(x.body for x in store.objects.values())
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 1
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2
    metrics = runtime.metrics.render().decode()
    assert (
        _metric_sample(
            metrics, 'saas_slo_stage_duration_seconds_count{stage="admission",outcome="success"}'
        )
        == 1
    )
    assert (
        _metric_sample(
            metrics, 'saas_slo_stage_duration_seconds_count{stage="admission",outcome="failure"}'
        )
        == 0
    )
    assert 'operation="run_event_ack",outcome="blocked"} 1' in metrics
    assert (
        _metric_sample(
            metrics, 'saas_slo_stage_duration_seconds_count{stage="admission",outcome="replayed"}'
        )
        == 1
    )


def test_rolled_back_commit_never_publishes_a_durable_ack(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, store = _runtime(factory)

    def reject(_connection):
        raise RuntimeError("injected commit rejection")

    engine = factory.kw["bind"]
    sa.event.listen(engine, "commit", reject)
    try:
        with runtime_scope(runtime), pytest.raises(RuntimeError, match="commit rejection"):
            admit()
    finally:
        sa.event.remove(engine, "commit", reject)
    assert store.objects == {}
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 0
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 0


def test_worker_lease_mutation_uses_same_independent_prefix(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, _ = _runtime(factory)
    with runtime_scope(runtime):
        admitted = admit()
        lease = service.claim_next_run(
            worker_id="owned-worker", lease_duration=timedelta(minutes=1)
        )
    assert lease is not None
    head, _ = runtime.witness.checkpoint(str(scope.tenant_id), str(admitted.run_id))
    assert head["sequence"] == 3


def test_event_deleted_after_ack_is_not_hidden_by_current_db_counts(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, _ = _runtime(factory)
    with runtime_scope(runtime):
        admitted = admit()
    # Fault bypasses the application to simulate a restore/truncation error.
    with factory.kw["bind"].begin() as connection:
        connection.execute(
            sa.delete(RunEventRecord).where(
                RunEventRecord.run_id == admitted.run_id, RunEventRecord.sequence == 2
            )
        )
        connection.execute(
            sa.update(RunRecord).where(RunRecord.id == admitted.run_id).values(event_sequence=1)
        )
    with runtime_scope(runtime), pytest.raises(WitnessConflict, match="regressed"):
        admit()


def test_http_path_never_backfills_an_unbounded_old_history(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    admitted = admit()
    runtime, store = _runtime(factory)
    runtime.witness.max_segment = 1
    runtime.witness.bind_epoch()  # Production startup binds the epoch before HTTP admission.
    before = dict(store.objects)
    with runtime_scope(runtime), pytest.raises(WitnessBackfillRequired):
        admit()
    assert store.objects == before
    assert admitted.run_id is not None


def test_event_page_ack_does_not_backfill_long_history_and_detects_content_change(
    execution_control_plane,
):
    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    runtime, store = _runtime(factory)
    runtime.witness.max_segment = 1
    with runtime_scope(runtime):
        page = service.replay_events(
            request,
            project_id=scope.project_id,
            run_id=admitted.run_id,
            after_sequence=1,
            limit=1,
        )
    assert [e.sequence for e in page] == [2]
    assert len(store.objects) == 3  # Epoch + exact event + max-ACK floor; no chain prefix.
    assert runtime.witness.checkpoint(str(scope.tenant_id), str(admitted.run_id))[0] is None
    with factory.kw["bind"].begin() as connection:
        connection.execute(
            sa.update(RunEventRecord)
            .where(
                RunEventRecord.run_id == admitted.run_id,
                RunEventRecord.sequence == 2,
            )
            .values(payload={"changed": "restored inconsistent source"})
        )
    with runtime_scope(runtime), pytest.raises(WitnessConflict, match="content changed"):
        service.replay_events(
            request,
            project_id=scope.project_id,
            run_id=admitted.run_id,
            after_sequence=1,
            limit=1,
        )


def test_source_connection_is_returned_before_any_independent_store_io(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, store = _runtime(factory)
    checked_out = 0
    engine = factory.kw["bind"]

    def checkout(*_args):
        nonlocal checked_out
        checked_out += 1

    def checkin(*_args):
        nonlocal checked_out
        checked_out -= 1

    original_read, original_put = store.read, store.conditional_put

    def read(*args, **kwargs):
        assert checked_out == 0, "source pool lease overlaps independent storage I/O"
        return original_read(*args, **kwargs)

    def put(*args, **kwargs):
        assert checked_out == 0, "source pool lease overlaps independent storage I/O"
        return original_put(*args, **kwargs)

    store.read, store.conditional_put = read, put
    sa.event.listen(engine, "checkout", checkout)
    sa.event.listen(engine, "checkin", checkin)
    try:
        with runtime_scope(runtime):
            admit()
    finally:
        sa.event.remove(engine, "checkout", checkout)
        sa.event.remove(engine, "checkin", checkin)
    assert checked_out == 0


def test_nested_savepoint_rollback_never_acknowledges_discarded_events(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    runtime, store = _runtime(factory)
    with runtime_scope(runtime):
        admitted = _admit(service, scope, request)()
    original = dict(store.objects)
    with factory.begin() as db:
        service._apply_request_context(db, request)
        run = db.get(RunRecord, admitted.run_id)
        with pytest.raises(ValueError, match="discard nested"):
            with db.begin_nested():
                service._append_event(
                    db,
                    run,
                    event_type="run.test.discarded",
                    payload={},
                    trace_id="discarded-savepoint",
                )
                db.flush()
                raise ValueError("discard nested")
    assert store.objects == original
    with factory() as db:
        assert db.get(RunRecord, admitted.run_id).event_sequence == 2
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2


class _DurableTestStore(_Store):
    """Separate fsynced test directory used only by actual SIGKILL qualification."""

    def __init__(self, directory, *, kill_after=None):
        from pathlib import Path

        super().__init__()
        self.directory = Path(directory)
        self.kill_after = kill_after
        self.puts = 0

    def read(self, key):
        path = self.directory / key
        if not path.exists():
            return None
        body = path.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        return StoredObject(body, digest, digest)

    def first(self, prefix):
        paths = sorted((self.directory / prefix).glob("*.json"))
        if not paths:
            return None
        key = str(paths[0].relative_to(self.directory))
        return key, self.read(key)

    def conditional_put(self, key, body, *, expected_etag):
        import os
        import signal

        if self.kill_after == 0:
            os.kill(os.getpid(), signal.SIGKILL)
        previous = self.read(key)
        if (None if previous is None else previous.etag) != expected_etag:
            raise WitnessConflict("independent file conditional conflict")
        path = self.directory / key
        path.parent.mkdir(parents=True, exist_ok=True)
        # No source transaction/connection shares this separate durability boundary.
        with path.open("xb" if previous is None else "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.puts += 1
        if self.kill_after == self.puts:
            os.kill(os.getpid(), signal.SIGKILL)
        return self.read(key)


def _disk_admit(payload, *, crash):
    from uuid import UUID

    from sqlalchemy.orm import sessionmaker

    from saas.compatibility import RequestContext
    from saas.control_plane import ExecutionControlPlane

    factory = sessionmaker(sa.create_engine(payload["url"]), expire_on_commit=False)
    store = _DurableTestStore(
        payload["witness_directory"], kill_after=payload["kill_after"] if crash else None
    )
    runtime = SloRuntime(
        SloMetrics(),
        RunEventWitness(
            store,
            product_revision="a" * 40,
            key_version="v1",
            hmac_key=b"x" * 32,
        ),
    )
    install_session_witness(factory, runtime)
    context = {
        key: UUID(value)
        if key in {"actor_id", "tenant_id", "space_id", "project_id"} and isinstance(value, str)
        else value
        for key, value in payload["request"].items()
    }
    request = RequestContext(**context)
    try:
        with runtime_scope(runtime):
            return ExecutionControlPlane(factory).admit_run(
                request,
                project_id=UUID(payload["project_id"]),
                task_id=UUID(payload["task_id"]),
                session_id=None,
                input_payload={"prompt": "private customer text"},
                quota_resource="run_units",
                quota_units=1,
                idempotency_key="sigkill-exact-retry",
                revisions=_revisions(),
            )
    finally:
        factory.kw["bind"].dispose()


@pytest.mark.parametrize("kill_after", [0, 1], ids=["before-witness", "partial-witness"])
def test_actual_sigkill_after_db_commit_recovers_without_duplicate_effects(
    execution_control_plane,
    tmp_path,
    kill_after,
):
    import json
    import signal
    import sqlite3
    import subprocess
    import sys
    from dataclasses import asdict

    factory, service, scope, request = execution_control_plane
    service.configure_quota(
        request, project_id=scope.project_id, resource="run_units", limit_units=3
    )
    task = service.create_task(request, project_id=scope.project_id, title="Actual crash boundary")
    database = tmp_path / "actual-source.db"
    raw = factory.kw["bind"].raw_connection()
    try:
        with sqlite3.connect(database) as target:
            raw.driver_connection.backup(target)
    finally:
        raw.close()
    payload = {
        "url": "sqlite:///" + str(database),
        "request": asdict(request),
        "task_id": str(task),
        "project_id": str(scope.project_id),
        "witness_directory": str(tmp_path / "independent-ack"),
        "kill_after": kill_after,
    }
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import json,sys;"
            "from tests.saas.test_slo_observability import _disk_admit;"
            "_disk_admit(json.load(sys.stdin),crash=True)",
        ],
        input=json.dumps(payload, default=str).encode(),
        capture_output=True,
        timeout=20,
    )
    assert child.returncode == -signal.SIGKILL, child.stderr.decode()
    engine = sa.create_engine(payload["url"])
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
            assert connection.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2
            assert (
                connection.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord))
                == 1
            )
        replay = _disk_admit(payload, crash=False)
        assert replay.replayed
        with engine.connect() as connection:
            assert connection.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1
            assert connection.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 2
            assert (
                connection.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord))
                == 1
            )
    finally:
        engine.dispose()


def _public_identity(factory, scope):
    from datetime import UTC, datetime
    from uuid import uuid4

    from saas.control_plane.api_credential_models import ApiCredentialRecord, ServiceAccountRecord
    from saas.control_plane.api_credentials import ValidatedApiCredential
    from tests.saas.test_public_api_postgresql import _public_service

    account_id, credential_id = uuid4(), uuid4()
    now = datetime.now(UTC)
    permissions = {"run.read_metadata", "run.read_content", "run.cancel"}
    with factory.begin() as db:
        db.add(
            ServiceAccountRecord(
                id=account_id,
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                project_id=scope.project_id,
                name="Witness qualification",
                steward_user_id=scope.owner_id,
                created_by=scope.owner_id,
                status="active",
                security_version=1,
            )
        )
        db.flush()
        db.add(
            ApiCredentialRecord(
                id=credential_id,
                tenant_id=scope.tenant_id,
                service_account_id=account_id,
                name="Test-only credential",
                token_hash=credential_id.hex * 2,
                display_prefix=credential_id.hex,
                permission_scopes=sorted(permissions),
                allowed_networks=[],
                account_security_version=1,
                status="active",
                expires_at=now + timedelta(hours=1),
                created_by=scope.owner_id,
            )
        )
    principal = ValidatedApiCredential(
        credential_id,
        account_id,
        scope.tenant_id,
        scope.space_id,
        scope.project_id,
        1,
        frozenset(permissions),
        now,
        now + timedelta(hours=1),
    )
    return _public_service(factory), principal


def test_metadata_content_and_run_list_do_not_add_witness_dependencies(execution_control_plane):
    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    public, principal = _public_identity(factory, scope)
    runtime, store = _runtime(factory)
    runtime.witness.max_segment = 1

    def no_storage(*_args, **_kwargs):
        raise AssertionError("metadata read unexpectedly accessed independent ACK witness")

    store.read = store.first = store.conditional_put = no_storage
    with runtime_scope(runtime):
        assert (
            public.get_run(principal, project_id=scope.project_id, run_id=admitted.run_id).id
            == admitted.run_id
        )
        assert public.get_run_content(
            principal, project_id=scope.project_id, run_id=admitted.run_id
        ).input == {"prompt": "private customer text"}
        assert (
            len(
                public.list_runs(
                    principal, project_id=scope.project_id, cursor=None, limit=10
                ).items
            )
            == 1
        )


def test_cached_public_cancel_rechecks_independent_ack_after_postcommit_failure(
    execution_control_plane,
):
    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    public, principal = _public_identity(factory, scope)
    runtime, store = _runtime(factory)
    with factory() as db:
        version = db.get(RunRecord, admitted.run_id).version
    arguments = {
        "project_id": scope.project_id,
        "run_id": admitted.run_id,
        "reason": "cancel test",
        "expected_version": version,
        "idempotency_key": "same-cancel",
        "trace_id": "cancel-ack",
    }
    store.fail = True
    with runtime_scope(runtime), pytest.raises(WitnessUnavailable):
        public.cancel_run(principal, **arguments)
    with factory() as db:
        assert db.get(RunRecord, admitted.run_id).status == "cancelled"
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 3
    store.fail = False
    with runtime_scope(runtime):
        replay = public.cancel_run(principal, **arguments)
    assert replay.replayed and replay.status == "cancelled"
    assert (
        runtime.witness.checkpoint(str(scope.tenant_id), str(admitted.run_id))[0]["sequence"] == 3
    )
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord)) == 3
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 1


def test_real_cookie_auth_and_context_resolution_report_eligible_and_denied_separately(
    execution_control_plane,
):
    from fastapi import Response
    from fastapi.testclient import TestClient

    from tests.saas.test_http_cookie_auth import _build_fastapi_app, _login

    factory, _service, _scope, _request = execution_control_plane
    runtime, _store = _runtime(factory)
    app, context = _build_fastapi_app()

    @app.get("/saas/admin/slo-test-dependency")
    def unavailable():
        return Response(status_code=503)

    with runtime_scope(runtime), TestClient(app) as client:
        denied = client.post(
            "/saas/auth/login", json={"email": "http@example.com", "password": "wrong-password"}
        )
        assert denied.status_code == 401
        _login(client)
        response = client.get(
            "/v1/protected",
            headers={
                "x-saas-tenant-id": context["tenant_id"],
                "x-saas-space-id": context["space_id"],
            },
        )
        assert response.status_code == 200
        assert client.get("/saas/admin/slo-test-dependency").status_code == 503
    metrics = runtime.metrics.render().decode()
    assert 'operation="auth_login",outcome="success"} 1' in metrics
    assert 'operation="auth_login",outcome="excluded"} 1' in metrics
    assert 'operation="auth_management",outcome="failure"} 1' in metrics
    assert (
        _metric_sample(
            metrics, 'saas_slo_stage_duration_seconds_count{stage="resolve",outcome="success"}'
        )
        > 0
    )
    assert (
        _metric_sample(
            metrics, 'saas_slo_stage_duration_seconds_count{stage="resolve_db",outcome="success"}'
        )
        > 0
    )
    assert "wrong-password" not in metrics and context["user_id"] not in metrics


@pytest.mark.parametrize("historical_events", [129, 5003])
def test_preupgrade_long_run_new_mutation_recovers_in_bounded_background_segments(
    execution_control_plane,
    historical_events,
):
    from datetime import UTC, datetime
    from uuid import uuid4

    from saas.control_plane.rls import RlsContext
    from saas.production.observability import recover_run_prefix

    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    with factory.begin() as db:
        run = db.get(RunRecord, admitted.run_id)
        rows = [
            RunEventRecord(
                id=uuid4(),
                tenant_id=scope.tenant_id,
                space_id=scope.space_id,
                project_id=scope.project_id,
                run_id=run.id,
                sequence=n,
                event_type="run.progress",
                payload={"progress": n},
                trace_id="pre-upgrade-history",
                created_at=datetime.now(UTC),
            )
            for n in range(3, historical_events + 1)
        ]
        db.add_all(rows)
        run.event_sequence = historical_events
    runtime, store = _runtime(factory)
    with runtime_scope(runtime), pytest.raises(WitnessBackfillRequired):
        service.request_cancel(
            request,
            project_id=scope.project_id,
            run_id=admitted.run_id,
            reason="new mutation of old long Run",
        )
    key = (scope.tenant_id, scope.space_id, scope.project_id, admitted.run_id)
    prior_put = store.conditional_put
    write_counts = []

    def bounded_put(*args, **kwargs):
        write_counts.append(1)
        return prior_put(*args, **kwargs)

    store.conditional_put = bounded_put
    context = RlsContext(
        actor_id=request.actor_id,
        tenant_id=scope.tenant_id,
        space_id=scope.space_id,
        project_id=scope.project_id,
    )
    prior = 0
    for _ in range(50):
        result = recover_run_prefix(factory, runtime, key, context, segments=1)
        assert 0 <= result["witness_cursor"] - prior <= 128
        assert len(write_counts) <= 128 * 2 + 1
        write_counts.clear()
        prior = result["witness_cursor"]
        if result["caught_up"]:
            break
    assert result["caught_up"] and result["source_cursor"] == historical_events + 1
    with runtime_scope(runtime):
        replay = service.request_cancel(
            request,
            project_id=scope.project_id,
            run_id=admitted.run_id,
            reason="new mutation of old long Run",
        )
    assert replay.replayed and replay.status == "cancelled"
    with factory() as db:
        assert (
            db.scalar(sa.select(sa.func.count()).select_from(RunEventRecord))
            == historical_events + 1
        )
        assert db.scalar(sa.select(sa.func.count()).select_from(QuotaReservationRecord)) == 1


def test_onboarding_sql_claims_only_its_seven_routes_and_preserves_other_dlq_state():
    from datetime import UTC, datetime
    from uuid import uuid4

    from sqlalchemy.orm import Session, sessionmaker
    from sqlalchemy.pool import StaticPool

    from saas.control_plane import ControlPlaneOutboxEvent, OutboxDispatcher, SaasBase
    from saas.control_plane.onboarding import OnboardingOutboxPublisher
    from saas.control_plane.outbox import OutboxPublishError

    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SaasBase.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False, class_=Session)
    onboarding = OnboardingOutboxPublisher(
        registrations=None, coordinator=None, envelopes=None, email_sender=None
    )
    routes = onboarding.claim_routes
    assert routes is not None and len(routes) == 7
    assert all(route.payload_event_type is None for route in routes)
    owned, unowned = set(), set()
    with factory.begin() as db:
        for aggregate, event_type in [
            *((route.aggregate_type, route.event_type) for route in routes),
            ("billing", "billing.usage.recorded"),
            ("platform_support", "platform.audit.persisted"),
            ("run", "run.event.persisted"),
            ("billing", "onboarding.tenant.requested"),
            ("tenant_onboarding", "onboarding.unknown.requested"),
        ]:
            event_id = uuid4()
            (
                owned
                if any(
                    route.aggregate_type == aggregate and route.event_type == event_type
                    for route in routes
                )
                else unowned
            ).add(event_id)
            db.add(
                ControlPlaneOutboxEvent(
                    id=event_id,
                    tenant_id=None,
                    aggregate_type=aggregate,
                    aggregate_key="synthetic-acceptance",
                    event_type=event_type,
                    idempotency_key=str(event_id),
                    request_hash="a" * 64,
                    payload={"event_type": "run.queued"},
                    attempt_count=0,
                )
            )
    published = []

    class Consumer:
        def publish(self, **event):
            published.append(event["event_id"])

    dispatcher = OutboxDispatcher(factory, Consumer(), claim_routes=routes)
    result = dispatcher.dispatch_once(now=datetime.now(UTC))
    assert (result.claimed, result.published, result.failed, result.quarantined) == (7, 7, 0, 0)
    assert set(published) == owned
    with factory() as db:
        for event_id in unowned:
            row = db.get(ControlPlaneOutboxEvent, event_id)
            assert row.attempt_count == 0 and row.claim_token is None
            assert row.claimed_at is None and row.published_at is None
            assert row.quarantined_at is None
    with pytest.raises(OutboxPublishError):
        onboarding.publish(
            event_id=uuid4(),
            event_type="billing.usage.recorded",
            aggregate_type="billing",
            aggregate_key="synthetic",
            payload={},
        )
    fallback = OnboardingOutboxPublisher(
        registrations=None,
        coordinator=None,
        envelopes=None,
        email_sender=None,
        fallback=Consumer(),
    )
    assert fallback.claim_routes is None
    engine.dispose()


def test_hmac_epoch_cannot_silently_reinitialize_same_product_key_version():
    store = _Store()
    first = RunEventWitness(store, product_revision="a" * 40, key_version="v1", hmac_key=b"a" * 32)
    first.bind_epoch()
    before = dict(store.objects)
    same = RunEventWitness(store, product_revision="a" * 40, key_version="v1", hmac_key=b"a" * 32)
    same.bind_epoch()
    assert store.objects == before
    changed = RunEventWitness(
        store, product_revision="a" * 40, key_version="v1", hmac_key=b"b" * 32
    )
    with pytest.raises(WitnessConflict, match="epoch key binding changed"):
        changed.checkpoint("tenant", "run")
    assert store.objects == before
    for key_version in ("../escape", "a/b", "", "x" * 65):
        with pytest.raises(ValueError):
            RunEventWitness(
                store, product_revision="a" * 40, key_version=key_version, hmac_key=b"a" * 32
            )


def test_admission_metric_ends_at_real_db_commit_before_independent_witness_io(
    execution_control_plane,
    monkeypatch,
):
    import types

    import saas.observability as observations

    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, store = _runtime(factory)
    clock = [0.0]
    monkeypatch.setattr(observations, "time", types.SimpleNamespace(monotonic=lambda: clock[0]))
    original = store.read

    def delayed_independent_io(key):
        clock[0] += 100.0
        return original(key)

    store.read = delayed_independent_io
    with runtime_scope(runtime):
        result = admit()
    assert result.run_id is not None and clock[0] >= 100.0
    assert (
        b'saas_slo_stage_duration_seconds_sum{stage="admission",outcome="success"} 0.000000000'
        in runtime.metrics.render()
    )
    with factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == 1


def test_process_configuration_is_explicit_bounded_private_and_failclosed(tmp_path, monkeypatch):
    import json

    from saas.production import observability as production

    monkeypatch.delenv("OMNIGENT_SAAS_SLO_CONFIG_FILE", raising=False)
    assert production.configured_runtime() is None
    profile = tmp_path / "private-input"
    profile.write_bytes(b"synthetic-value")
    profile.chmod(0o600)
    assert production._private(str(profile), 32) == b"synthetic-value"
    profile.chmod(0o640)
    with pytest.raises(WitnessUnavailable):
        production._private(str(profile), 32)
    profile.chmod(0o600)
    with pytest.raises(WitnessUnavailable):
        production._private(str(profile), 2)
    alias = tmp_path / "symlink"
    alias.symlink_to(profile)
    with pytest.raises(OSError):
        production._private(str(alias), 32)
    profile.write_text(
        json.dumps({"purpose": "wrong-purpose", "never-log": "synthetic-secret-marker"})
    )
    monkeypatch.setenv("OMNIGENT_SAAS_SLO_CONFIG_FILE", str(profile))
    with pytest.raises(WitnessUnavailable, match="configured SLO process dependency") as error:
        production.configured_runtime()
    assert "synthetic-secret-marker" not in str(error.value)


def test_same_cursor_terminal_projection_tamper_is_rejected_on_actual_mutation_replay(
    execution_control_plane,
):
    factory, service, scope, request = execution_control_plane
    admit = _admit(service, scope, request)
    runtime, _ = _runtime(factory)
    with runtime_scope(runtime):
        admitted = admit()
        service.request_cancel(
            request, project_id=scope.project_id, run_id=admitted.run_id, reason="stop"
        )
    with factory.kw["bind"].begin() as connection:
        connection.execute(
            sa.update(RunRecord).where(RunRecord.id == admitted.run_id).values(status="failed")
        )
    with runtime_scope(runtime), pytest.raises(WitnessConflict, match="state projection"):
        admit()


def test_legitimate_heartbeat_version_without_new_event_does_not_conflict(
    execution_control_plane,
):
    factory, service, _scope, request = execution_control_plane
    admit = _admit(service, _scope, request)
    runtime, _ = _runtime(factory)
    with runtime_scope(runtime):
        admitted = admit()
        lease = service.claim_next_run(
            worker_id="owned-worker", lease_duration=timedelta(minutes=2)
        )
        assert lease is not None
        service.heartbeat(
            run_id=admitted.run_id,
            lease_token=lease.lease_token,
            fence_token=lease.fence_token,
            lease_duration=timedelta(minutes=2),
        )
        replayed = admit()
    assert replayed.replayed
    with factory() as db:
        run = db.get(RunRecord, admitted.run_id)
        assert run.event_sequence == 3 and run.version > run.event_sequence


def test_run_queued_consumer_actual_projection_commit_does_not_bypass_event_ack_replay(
    request,
):
    from saas.control_plane import RunDispatchRecord
    from tests.saas.test_run_dispatch_projection import _admit as admit
    from tests.saas.test_run_dispatch_projection import _project

    fixture = request.getfixturevalue("runtime_dispatch_fixture")
    run_id = admit(fixture, key="independent-consumer-failure")
    runtime, store = _runtime(fixture.factory)
    store.fail = True
    with runtime_scope(runtime), pytest.raises(WitnessUnavailable):
        _project(fixture, run_id)
    with fixture.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunDispatchRecord)) == 1
    store.fail = False
    with runtime_scope(runtime):
        result = _project(fixture, run_id)
    assert result.replayed and not result.projected
    with fixture.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunDispatchRecord)) == 1
    assert any("/acknowledged/" in key for key in store.objects)


def test_preview_creation_actual_cached_replay_recovers_child_run_ack(worktree_fixture):
    from datetime import UTC, datetime
    from uuid import uuid4

    from saas.control_plane.preview_execution import (
        PreviewExecutionControlPlane,
        PreviewExecutionPolicy,
    )
    from tests.saas.test_worktree_control_plane import (
        _allocate,
        _configure_worktree_quota,
        _finish_run,
        _lease_run,
        _ready,
        _repository_and_change_set,
    )

    fixture = worktree_fixture
    now = datetime.now(UTC).replace(microsecond=0)
    _, change_set = _repository_and_change_set(fixture, suffix="witness-preview")
    _configure_worktree_quota(fixture)
    source = _lease_run(fixture, change_set_id=change_set, key="witness-source", now=now)
    tree = _allocate(fixture, source, change_set, now=now + timedelta(seconds=2))
    _ready(fixture, tree, now=now + timedelta(seconds=3))
    fixture.worktrees.checkpoint(
        worktree_id=tree.worktree_id,
        runner_id=tree.runner_id,
        lease_generation=tree.lease_generation,
        run_fence_token=tree.run_fence_token,
        lease_token=tree.lease_token,
        head_revision="a" * 40,
        recovery_artifact_ref=f"artifact:{uuid4()}",
        environment_snapshot_ref=f"environment:{uuid4()}",
        dirty_after=False,
        trace_id="preview-witness-checkpoint",
        now=now + timedelta(seconds=4),
    )
    _finish_run(fixture, source, now=now + timedelta(seconds=5))
    fixture.worktrees.release(
        worktree_id=tree.worktree_id,
        runner_id=tree.runner_id,
        lease_generation=tree.lease_generation,
        run_fence_token=tree.run_fence_token,
        lease_token=tree.lease_token,
        final_change_set_status="committed",
        trace_id="preview-witness-release",
        now=now + timedelta(seconds=6),
    )
    fixture.execution.configure_quota(
        fixture.request, project_id=fixture.project_id, resource="preview_runs", limit_units=2
    )
    previews = PreviewExecutionControlPlane(
        fixture.factory,
        policy=PreviewExecutionPolicy(preview_root_domain="jxhh.com", exchange_hmac_key=b"p" * 32),
    )
    runtime, store = _runtime(fixture.factory)
    store.fail = True
    kwargs = {
        "project_id": fixture.project_id,
        "source_run_id": source.run_id,
        "preview_kind": "static_web_v1",
        "idempotency_key": "witness-preview-create-0001",
        "now": now + timedelta(seconds=7),
    }
    with runtime_scope(runtime), pytest.raises(WitnessUnavailable):
        previews.request_preview(fixture.request, **kwargs)
    with fixture.factory() as db:
        committed_runs = db.scalar(sa.select(sa.func.count()).select_from(RunRecord))
    store.fail = False
    with runtime_scope(runtime):
        result = previews.request_preview(fixture.request, **kwargs)
    assert result.replayed and result.child_run_id is not None
    with fixture.factory() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RunRecord)) == committed_runs
    head, _ = runtime.witness.checkpoint(str(fixture.request.tenant_id), str(result.child_run_id))
    assert head["sequence"] == 2


@pytest.mark.parametrize("api", ["execution", "public"])
@pytest.mark.parametrize("damage", ["first", "tail", "all", "head-regression"])
def test_actual_replay_pages_reject_requested_holes_and_empty_ack_regression(
    execution_control_plane, api, damage
):
    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    public, principal = _public_identity(factory, scope)
    runtime, _ = _runtime(factory)

    def replay(after=0):
        if api == "execution":
            return service.replay_events(
                request,
                project_id=scope.project_id,
                run_id=admitted.run_id,
                after_sequence=after,
                limit=10,
            )
        return public.list_run_events(
            principal,
            project_id=scope.project_id,
            run_id=admitted.run_id,
            after_sequence=after,
            cursor=None,
            limit=10,
        )

    with runtime_scope(runtime):
        replay()  # Only old-history page ACK, no complete chain-prefix checkpoint.
        assert runtime.witness.checkpoint(str(scope.tenant_id), str(admitted.run_id))[0] is None
        replay(after=2)  # A legitimate exhausted cursor remains successful.
    with factory.kw["bind"].begin() as connection:
        query = sa.delete(RunEventRecord).where(RunEventRecord.run_id == admitted.run_id)
        if damage in {"tail", "head-regression"}:
            query = query.where(RunEventRecord.sequence == 2)
        elif damage == "first":
            query = query.where(RunEventRecord.sequence == 1)
        connection.execute(query)
        if damage == "head-regression":
            connection.execute(
                sa.update(RunRecord)
                .where(RunRecord.id == admitted.run_id)
                .values(event_sequence=1)
            )
    with runtime_scope(runtime), pytest.raises(WitnessConflict):
        replay(after=1 if damage == "head-regression" else 0)


@pytest.mark.parametrize("bad", [False, True, None, "", "relative-ca.pem"])
def test_slo_tls_trust_rejects_implicit_or_boolean_verification(bad):
    from saas.production.observability import _validated_ca

    with pytest.raises(WitnessUnavailable, match="explicit absolute"):
        _validated_ca(bad)


def test_slo_tls_trust_parses_only_bounded_owner_ca_files(tmp_path):
    from datetime import UTC, datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from saas.production.observability import _validated_ca

    path = tmp_path / "ca.pem"
    path.write_bytes(b"not a certificate")
    path.chmod(0o600)
    with pytest.raises(WitnessUnavailable, match="valid trust"):
        _validated_ca(str(path))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated SLO test trust")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    assert _validated_ca(str(path)) == str(path)
    path.chmod(0o666)
    with pytest.raises(WitnessUnavailable, match="owner-only"):
        _validated_ca(str(path))


def test_page_floor_snapshot_allows_later_legitimate_concurrent_ack_without_false_loss():
    from saas.production.slo_witness import WitnessEvent

    store = _Store()
    witness = RunEventWitness(
        store, product_revision="a" * 40, key_version="v1", hmac_key=b"x" * 32
    )
    first = WitnessEvent(1, {"actual": "one"})
    second = WitnessEvent(2, {"actual": "two"})
    floor = witness.observed_floor("tenant", "run")
    # Another real source statement saw and ACKed event2 after ours saw head1.
    witness.acknowledge_page(
        "tenant",
        "run",
        (first, second),
        after_sequence=0,
        source_head=2,
        limit=10,
        minimum_source_head=floor,
    )
    witness.acknowledge_page(
        "tenant",
        "run",
        (first,),
        after_sequence=0,
        source_head=1,
        limit=10,
        minimum_source_head=floor,
    )
    assert witness.observed_floor("tenant", "run") == 2
    # A later source statement starts after that ACK: head1 really is stale/lost.
    with pytest.raises(WitnessConflict):
        witness.acknowledge_page(
            "tenant",
            "run",
            (),
            after_sequence=1,
            source_head=1,
            limit=10,
            minimum_source_head=witness.observed_floor("tenant", "run"),
        )


def test_recovery_budget_stops_within_segment_after_one_inflight_call(
    execution_control_plane, monkeypatch
):
    import saas.production.slo_witness as module
    from saas.control_plane.rls import RlsContext
    from saas.production.observability import recover_run_prefix

    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    runtime, store = _runtime(factory)
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    original = store.read
    calls = []

    def delayed(key):
        calls.append(key)
        result = original(key)
        clock[0] += 2.0  # An actual in-flight call may finish after the work budget.
        return result

    store.read = delayed
    result = recover_run_prefix(
        factory,
        runtime,
        (scope.tenant_id, scope.space_id, scope.project_id, admitted.run_id),
        RlsContext(
            tenant_id=scope.tenant_id, space_id=scope.space_id, project_id=scope.project_id
        ),
        segments=100,
        deadline_seconds=1,
    )
    assert result["deadline_exhausted"] and not result["caught_up"]
    assert result["segments"] == 0 and len(calls) == 1 and store.objects == {}


@pytest.mark.parametrize("rejected", ["project", "permission", "revoked", "run"])
def test_public_event_scope_denials_precede_any_independent_witness_io(
    execution_control_plane,
    rejected,
):
    from dataclasses import replace
    from uuid import uuid4

    from saas.control_plane.api_credential_models import ApiCredentialRecord
    from saas.control_plane.public_api import PublicApiError

    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    public, principal = _public_identity(factory, scope)
    runtime, _ = _runtime(factory)
    calls = []

    class Unavailable(_Store):
        def read(self, key):
            calls.append(key)
            raise WitnessUnavailable("independent service unavailable")

        def first(self, prefix):
            calls.append(prefix)
            raise WitnessUnavailable("independent service unavailable")

    runtime.witness.store = Unavailable()
    project, run = scope.project_id, admitted.run_id
    expected = "invalid_api_credential"
    if rejected == "project":
        project = uuid4()
    elif rejected == "permission":
        principal = replace(principal, permission_scopes=frozenset({"run.read_metadata"}))
        expected = "permission_denied"
    elif rejected == "revoked":
        with factory.begin() as db:
            credential = db.get(ApiCredentialRecord, principal.credential_id)
            credential.status, credential.revoked_at = "revoked", datetime.now(UTC)
    else:
        run = uuid4()
        expected = "run_not_found"
    with runtime_scope(runtime), pytest.raises(PublicApiError) as denied:
        public.list_run_events(principal, project_id=project, run_id=run, cursor=None, limit=10)
    assert denied.value.code == expected
    assert calls == []


def test_public_page_rechecks_real_revocation_after_authorized_floor_io_without_db_lease(
    execution_control_plane,
):
    from saas.control_plane.api_credential_models import ApiCredentialRecord
    from saas.control_plane.public_api import PublicApiError

    factory, service, scope, request = execution_control_plane
    admitted = _admit(service, scope, request)()
    public, principal = _public_identity(factory, scope)
    runtime, _ = _runtime(factory)
    checked_out = [0]
    witnessed = []

    @sa.event.listens_for(factory.kw["bind"], "checkout")
    def checkout(*_args):
        checked_out[0] += 1

    @sa.event.listens_for(factory.kw["bind"], "checkin")
    def checkin(*_args):
        checked_out[0] -= 1

    class InterveningRevocation(_Store):
        def read(self, key):
            if not witnessed:
                witnessed.append(checked_out[0])
                with factory.begin() as db:
                    credential = db.get(ApiCredentialRecord, principal.credential_id)
                    credential.status, credential.revoked_at = "revoked", datetime.now(UTC)
            return super().read(key)

    store = InterveningRevocation()
    runtime.witness.store = store
    with runtime_scope(runtime), pytest.raises(PublicApiError) as denied:
        public.list_run_events(
            principal, project_id=scope.project_id, run_id=admitted.run_id, cursor=None, limit=10
        )
    assert denied.value.code == "invalid_api_credential"
    assert witnessed == [0] and checked_out == [0]
    assert not any("events/" in key or "acknowledged-heads/" in key for key in store.objects)
