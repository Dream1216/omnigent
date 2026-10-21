"""Bounded SaaS SLI measurements and post-commit independent event witnesses."""

from __future__ import annotations

import contextvars
import functools
import inspect
import threading
import time
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from saas.production.slo_witness import (
    RunEventWitness,
    WitnessConflict,
    WitnessEvent,
    WitnessUnavailable,
)

_CONTEXT = "saas_verified_observation_rls_context"
_RUNS = "saas_observation_required_runs"
_WRITES = "saas_observation_run_event_writes"
_PAGES = "saas_observation_required_pages"
_SKIP = "saas_observation_readback"
_RUNTIME: SloRuntime | None = None
_ADMISSION_TIMER = contextvars.ContextVar[dict[str, Any] | None](
    "saas_admission_timer", default=None
)
_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)
_STAGES = {
    "resolve",
    "resolve_db",
    "resolve_snapshot_live",
    "resolve_cache",
    "admission",
    "outbox_visibility",
    "outbox_usage_delivery",
    "outbox_audit_delivery",
    "snapshot_age",
    "revocation_invalidation",
    "auth_login",
    "auth_session",
    "auth_api_key",
    "auth_context",
    "auth_management",
}
_OUTCOMES = {"success", "failure", "replayed", "excluded", "denied", "blocked"}
_OPERATIONS = {
    "auth_eligible",
    "auth_login",
    "auth_session",
    "auth_api_key",
    "auth_context",
    "auth_management",
    "auth_excluded",
    "run_event_ack",
    "run_event_integrity",
    "witness_readback",
    "revocation_healthy",
    "revocation_degraded",
    "coverage_gap",
}


class SloMetrics:
    """Reuse the DCP metric contract: bounded enums, no tenant or request labels."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Fixed enum cross-products: 78 counters + 90 histograms (1,440 samples).
        # Zero is the initial event count, never evidence of successful traffic,
        # witness/pool health, catch-up, or a nonempty SLO denominator. Creating
        # each series before its first event preserves that event in rate/increase.
        self._counts = {
            (operation, outcome): 0 for operation in _OPERATIONS for outcome in _OUTCOMES
        }
        self._durations = {
            (stage, outcome): [0.0] * (len(_BUCKETS) + 2)
            for stage in _STAGES
            for outcome in _OUTCOMES
        }
        self._pool_engines: weakref.WeakValueDictionary[int, sa.engine.Engine] = (
            weakref.WeakValueDictionary()
        )
        self._pool_refusals = 0

    def register_pool_engine(self, engine: object) -> None:
        """Observe the existing bounded pool; never acquire a DB connection."""
        with self._lock:
            if not isinstance(engine, sa.engine.Engine) or (
                id(engine) not in self._pool_engines and len(self._pool_engines) >= 32
            ):
                self._pool_refusals += 1
                return
            self._pool_engines[id(engine)] = engine

    def _pool_metrics(self) -> list[str]:
        # Read current Engine.pool on every scrape, including after dispose().
        # Engine URLs/credentials are never rendered or used for DB I/O.
        pools = {}
        for engine in list(self._pool_engines.values()):
            pool = engine.pool
            pools[id(pool)] = pool
        checked_out = bounded_capacity = unbounded = errors = 0
        for pool in pools.values():
            try:
                if not isinstance(pool, sa.pool.QueuePool):
                    raise ValueError("pool has no bounded QueuePool counters")
                size, overflow, checked = pool.size(), pool._max_overflow, pool.checkedout()
                if (
                    type(size) is not int
                    or type(overflow) is not int
                    or type(checked) is not int
                    or size < 0
                    or overflow < -1
                    or checked < 0
                ):
                    raise ValueError("invalid pool counters")
                checked_out += checked
                if size == 0 or overflow == -1:
                    unbounded += 1
                else:
                    bounded_capacity += size + overflow
            except Exception:  # noqa: BLE001 -- pool errors may contain private connection data
                errors += 1
        samples = {
            "observed_count": len(pools),
            "checked_out_connections": checked_out,
            "bounded_capacity_connections": bounded_capacity,
            "unbounded_count": unbounded,
            "observation_errors": errors,
        }
        lines = []
        for name, value in samples.items():
            metric = "saas_slo_postgresql_pool_" + name
            lines.extend((f"# TYPE {metric} gauge", f"{metric} {value}"))
        lines.extend(
            (
                "# TYPE saas_slo_postgresql_pool_registration_refusals_total counter",
                f"saas_slo_postgresql_pool_registration_refusals_total {self._pool_refusals}",
            )
        )
        return lines

    def count(self, operation: str, outcome: str, amount: int = 1) -> None:
        if (
            operation not in _OPERATIONS
            or outcome not in _OUTCOMES
            or type(amount) is not int
            or amount < 0
        ):
            raise ValueError("metric labels must be bounded contract values")
        with self._lock:
            self._counts[(operation, outcome)] += amount

    def duration(self, stage: str, outcome: str, seconds: float) -> None:
        if stage not in _STAGES or outcome not in _OUTCOMES or not 0 <= seconds < float("inf"):
            raise ValueError("duration or metric labels are invalid")
        with self._lock:
            values = self._durations[(stage, outcome)]
            for index, bucket in enumerate(_BUCKETS):
                if seconds <= bucket:
                    values[index] += 1
            values[-2] += 1
            values[-1] += seconds

    def render(self) -> bytes:
        with self._lock:
            lines = [
                "# TYPE saas_slo_operations_total counter",
                "# TYPE saas_slo_stage_duration_seconds histogram",
            ]
            for (operation, outcome), value in sorted(self._counts.items()):
                lines.append(
                    f'saas_slo_operations_total{{operation="{operation}",'
                    f'outcome="{outcome}"}} {value}'
                )
            for (stage, outcome), values in sorted(self._durations.items()):
                for index, bucket in enumerate(_BUCKETS):
                    lines.append(
                        f'saas_slo_stage_duration_seconds_bucket{{stage="{stage}",'
                        f'outcome="{outcome}",le="{bucket:g}"}} {int(values[index])}'
                    )
                lines.append(
                    f'saas_slo_stage_duration_seconds_bucket{{stage="{stage}",'
                    f'outcome="{outcome}",le="+Inf"}} {int(values[-2])}'
                )
                lines.append(
                    f'saas_slo_stage_duration_seconds_count{{stage="{stage}",'
                    f'outcome="{outcome}"}} {int(values[-2])}'
                )
                lines.append(
                    f'saas_slo_stage_duration_seconds_sum{{stage="{stage}",'
                    f'outcome="{outcome}"}} {values[-1]:.9f}'
                )
            lines.extend(self._pool_metrics())
            return ("\n".join(lines) + "\n").encode()


@dataclass
class SloRuntime:
    metrics: SloMetrics
    witness: RunEventWitness

    def require_runs(
        self,
        factory: sessionmaker[Session],
        scopes: set[tuple[UUID, UUID, UUID, UUID]],
        context: object,
        *,
        recovery: bool = False,
    ) -> dict[tuple[UUID, UUID, UUID, UUID], tuple[int, int]]:
        """No DB transaction or row lock is held during independent-store I/O."""
        from saas.control_plane.execution_models import RunEventRecord, RunRecord
        from saas.control_plane.rls import RlsContext, apply_rls_context

        if not isinstance(context, RlsContext) or len(scopes) > 1024:
            raise WitnessUnavailable("witness requires one bounded verified RLS scope")
        progress = {}
        for tenant_id, space_id, project_id, run_id in sorted(scopes, key=str):
            if context.tenant_id is not None and context.tenant_id != tenant_id:
                raise WitnessConflict("witness cannot change the source tenant scope")
            previous = self.witness.checkpoint(str(tenant_id), str(run_id))
            old_sequence = 0 if previous[0] is None else previous[0]["sequence"]
            minimum_source_head = self.witness.observed_floor(str(tenant_id), str(run_id))
            with factory() as readback:
                readback.info[_SKIP] = True
                with readback.begin():
                    apply_rls_context(readback, context)
                    run = readback.scalar(
                        sa.select(RunRecord).where(
                            RunRecord.id == run_id,
                            RunRecord.tenant_id == tenant_id,
                            RunRecord.space_id == space_id,
                            RunRecord.project_id == project_id,
                        )
                    )
                    if run is None:
                        raise WitnessConflict(
                            "witnessed source Run is not visible in original scope"
                        )
                    if run.event_sequence < old_sequence:
                        raise WitnessConflict(
                            "source Run head regressed below durable ACK witness"
                        )
                    actual_head = run.event_sequence
                    terminal = run.terminal_at
                    if terminal is not None and terminal.tzinfo is None:
                        terminal = terminal.replace(tzinfo=UTC)
                    projection: dict[str, object] = {
                        "status": run.status,
                        "terminal_at": None
                        if terminal is None
                        else terminal.astimezone(UTC).isoformat(),
                    }
                    target_head = min(actual_head, old_sequence + self.witness.max_segment)
                    if not recovery and actual_head != target_head:
                        from saas.production.slo_witness import WitnessBackfillRequired

                        raise WitnessBackfillRequired(
                            "bounded background witness recovery required"
                        )
                    rows = tuple(
                        readback.scalars(
                            sa.select(RunEventRecord)
                            .where(
                                RunEventRecord.run_id == run_id,
                                RunEventRecord.tenant_id == tenant_id,
                                RunEventRecord.space_id == space_id,
                                RunEventRecord.project_id == project_id,
                                RunEventRecord.sequence >= max(1, old_sequence),
                                RunEventRecord.sequence <= target_head,
                            )
                            .order_by(RunEventRecord.sequence)
                            .limit(self.witness.max_segment + 1)
                        )
                    )
                    source_head = target_head
                    values = tuple(_witness_event(row) for row in rows)
            anchor = next((row for row in values if row.sequence == old_sequence), None)
            segment = tuple(row for row in values if row.sequence > old_sequence)
            self.witness.ensure_segment(
                str(tenant_id),
                str(run_id),
                source_head=source_head,
                events=segment,
                previous=previous,
                anchor=anchor,
                actual_source_head=actual_head,
                minimum_source_head=minimum_source_head,
            )
            if source_head == actual_head:
                self.witness.acknowledge_projection(
                    str(tenant_id), str(run_id), actual_head, projection
                )
            progress[(tenant_id, space_id, project_id, run_id)] = (source_head, actual_head)
            self.metrics.count("witness_readback" if recovery else "run_event_ack", "success")
        return progress


def _witness_event(row: Any) -> WitnessEvent:
    timestamp = row.created_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return WitnessEvent(
        row.sequence,
        {
            "id": str(row.id),
            "tenant_id": str(row.tenant_id),
            "space_id": str(row.space_id),
            "project_id": str(row.project_id),
            "run_id": str(row.run_id),
            "sequence": row.sequence,
            "event_type": row.event_type,
            "payload": row.payload,
            "trace_id": row.trace_id,
            "created_at": timestamp.astimezone(UTC).isoformat(),
        },
    )


def require_run_witness(session: Session, run: Any) -> None:
    if not session.info.get(_SKIP):
        session.info.setdefault(_RUNS, set()).add(
            (run.tenant_id, run.space_id, run.project_id, run.id)
        )


def capture_event_page_floor(factory, tenant_id, run_id) -> int:
    runtime = getattr(factory, "_saas_slo_witness", None)
    if runtime is None:
        return 0
    return runtime.witness.observed_floor(str(tenant_id), str(run_id))


def require_event_page_witness(
    session: Session,
    run: Any,
    rows: tuple[Any, ...],
    *,
    after_sequence: int,
    source_head: int,
    limit: int,
    minimum_source_head: int,
) -> None:
    """Capture even empty pages with their real cursor and statement-snapshot head."""
    if session.info.get(_SKIP):
        return
    scope = (run.tenant_id, run.space_id, run.project_id, run.id)
    _capture_event_ack(
        session,
        scope,
        rows,
        {
            "after_sequence": after_sequence,
            "source_head": source_head,
            "limit": limit,
            "minimum_source_head": minimum_source_head,
        },
    )


def require_event_ack_witness(session: Session, rows: tuple[Any, ...]) -> None:
    """An exact consumer event ACK is not an assertion of a whole API page."""
    if session.info.get(_SKIP) or not rows:
        return
    scope = (rows[0].tenant_id, rows[0].space_id, rows[0].project_id, rows[0].run_id)
    _capture_event_ack(session, scope, rows, None)


def _capture_event_ack(session, scope, rows, boundary):
    if len(rows) > 5000:
        raise WitnessUnavailable("event page exceeds original API bound")
    if any((r.tenant_id, r.space_id, r.project_id, r.run_id) != scope for r in rows):
        raise WitnessConflict("event page contains mixed source scopes")
    session.info.setdefault(_PAGES, []).append(
        (scope, tuple(_witness_event(r) for r in rows), boundary)
    )


def note_rls_context(session: Session, context: object) -> None:
    session.info[_CONTEXT] = context


def install_session_witness(factory: sessionmaker[Session], runtime: SloRuntime) -> None:
    """Guard writes and explicit replay ACKs; release source connection before I/O."""
    if getattr(factory, "_saas_slo_witness", None) is not None:
        if factory._saas_slo_witness is not runtime:
            raise WitnessUnavailable("session factory already has a different witness authority")
        return
    setattr(factory, "_saas_slo_witness", runtime)  # noqa: B010 - third-party runtime extension
    bind = factory.kw.get("bind")
    if isinstance(bind, sa.engine.Engine) and bind.dialect.name == "postgresql":
        runtime.metrics.register_pool_engine(bind)

    @sa.event.listens_for(factory, "after_begin")
    def begun(session: Session, _transaction: object, _connection: object) -> None:
        from saas.control_plane.rls import RlsContext

        session.info.setdefault(_CONTEXT, RlsContext())

    @sa.event.listens_for(factory, "after_transaction_create")
    def nested_started(session: Session, transaction: Any) -> None:
        if transaction.nested:
            session.info.setdefault("saas_slo_savepoints", {})[id(transaction)] = (
                set(session.info.get(_RUNS, set())),
                session.info.get(_CONTEXT),
                list(session.info.get(_PAGES, [])),
                session.info.get(_WRITES, False),
            )

    @sa.event.listens_for(factory, "after_soft_rollback")
    def rolled_back(session: Session, transaction: Any) -> None:
        if transaction.nested:
            snapshot = session.info.get("saas_slo_savepoints", {}).pop(id(transaction), None)
            if snapshot is not None:
                (
                    session.info[_RUNS],
                    session.info[_CONTEXT],
                    session.info[_PAGES],
                    session.info[_WRITES],
                ) = snapshot

    @sa.event.listens_for(factory, "after_flush")
    def capture(session: Session, _flush: object) -> None:
        if session.info.get(_SKIP):
            return
        from saas.control_plane.execution_models import RunEventRecord

        for row in session.new:
            if isinstance(row, RunEventRecord):
                session.info[_WRITES] = True
                session.info.setdefault(_RUNS, set()).add(
                    (row.tenant_id, row.space_id, row.project_id, row.run_id)
                )

    @sa.event.listens_for(factory, "after_commit")
    def committed(session: Session) -> None:
        if not session.in_nested_transaction() and not session.info.get(_SKIP):
            session.info["saas_slo_committed"] = True
            timer = _ADMISSION_TIMER.get()
            if timer is not None and session.info.get(_WRITES):
                timer["committed_at"] = time.monotonic()

    @sa.event.listens_for(factory, "after_transaction_end")
    def ended(session: Session, transaction: Any) -> None:
        if transaction.parent is not None or session.info.get(_SKIP):
            return
        did_commit = session.info.pop("saas_slo_committed", False)
        session.info.pop(_WRITES, None)
        session.info.pop("saas_slo_savepoints", None)
        scopes = session.info.pop(_RUNS, set())
        pages = session.info.pop(_PAGES, [])
        context = session.info.pop(_CONTEXT, None)
        if did_commit and (scopes or pages):
            try:
                if scopes:
                    runtime.require_runs(factory, scopes, context)
                for scope, events, boundary in pages:
                    if boundary is None:
                        runtime.witness.acknowledge_events(str(scope[0]), str(scope[3]), events)
                    else:
                        runtime.witness.acknowledge_page(
                            str(scope[0]), str(scope[3]), events, **boundary
                        )
                    runtime.metrics.count("run_event_ack", "success", len(events))
            except WitnessConflict:
                runtime.metrics.count("run_event_integrity", "failure")
                runtime.metrics.count("run_event_ack", "blocked")
                raise
            except Exception:
                runtime.metrics.count("coverage_gap", "blocked")
                runtime.metrics.count("run_event_ack", "blocked")
                raise


def activate_runtime(runtime: SloRuntime) -> None:
    global _RUNTIME
    if _RUNTIME is not None and _RUNTIME is not runtime:
        raise WitnessUnavailable("a process cannot replace its active witness namespace")
    _RUNTIME = runtime


def ensure_observed_factory(factory: sessionmaker[Session]) -> None:
    from saas.production.observability import configured_runtime

    runtime = current_runtime() or configured_runtime()
    if runtime is not None:
        install_session_witness(factory, runtime)


def current_runtime() -> SloRuntime | None:
    return _RUNTIME


@contextmanager
def runtime_scope(runtime: SloRuntime) -> Iterator[None]:
    global _RUNTIME
    old, _RUNTIME = _RUNTIME, runtime
    try:
        yield
    finally:
        _RUNTIME = old


@contextmanager
def _stage_timer(stage: str) -> Iterator[dict[str, Any]]:
    start = time.monotonic()
    measured = {"outcome": "failure", "omitted": False, "committed_at": None}
    token = _ADMISSION_TIMER.set(measured) if stage == "admission" else None
    try:
        yield measured
    finally:
        runtime = current_runtime()
        if runtime is not None and not measured["omitted"]:
            # SLO-ADMISSION ends at actual DB commit. Independent ACK witness
            # latency/failure is measured separately and cannot shift that boundary.
            committed = measured["committed_at"]
            stop = time.monotonic() if committed is None else committed
            outcome = measured["outcome"] if committed is None else "success"
            runtime.metrics.duration(stage, outcome, stop - start)
        if token is not None:
            _ADMISSION_TIMER.reset(token)


def measure_stage(
    stage: str, *, omit_none: bool = False
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(function):

            @functools.wraps(function)
            async def asynchronous(*args: Any, **kwargs: Any) -> Any:
                with _stage_timer(stage) as measured:
                    result = await function(*args, **kwargs)
                    measured["omitted"] = omit_none and result is None
                    measured["outcome"] = (
                        "replayed" if getattr(result, "replayed", False) else "success"
                    )
                    return result

            return asynchronous

        @functools.wraps(function)
        def synchronous(*args: Any, **kwargs: Any) -> Any:
            with _stage_timer(stage) as measured:
                result = function(*args, **kwargs)
                measured["omitted"] = omit_none and result is None
                measured["outcome"] = (
                    "replayed" if getattr(result, "replayed", False) else "success"
                )
                return result

        return synchronous

    return decorate


class SloHttpMiddleware:
    """Measure eligible original control-plane requests at their actual response start.

    Client and authorization failures are explicit excluded counters. HTTP 5xx and
    exceptions remain eligible failures, including dependency failure before identity
    validation. Static resources and first external identity redirect/login are not
    quietly added to the valid-request denominator. No credential value is retained.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        runtime = current_runtime()
        path = scope.get("path", "")
        if (
            runtime is None
            or scope.get("type") != "http"
            or not path.startswith(("/saas/", "/api/v1/", "/v1/"))
            or path.startswith(
                (
                    "/saas/auth/oidc/",
                    "/saas/auth/sso/",
                    "/saas/login",
                    "/saas/delivery/assets/",
                )
            )
            or path in {"/saas/production/ready", "/saas/production/version"}
        ):
            await self.app(scope, receive, send)
            return
        if path == "/saas/auth/login":
            operation = "auth_login"
        elif path.startswith("/api/v1/"):
            operation = "auth_api_key"
        elif path.startswith("/saas/context"):
            operation = "auth_context"
        elif path.startswith(("/saas/admin/", "/saas/platform/")):
            operation = "auth_management"
        else:
            operation = "auth_session"
        started, recorded = time.monotonic(), False

        def record(outcome: str) -> None:
            nonlocal recorded
            if not recorded:
                recorded = True
                runtime.metrics.count(operation, outcome)
                runtime.metrics.count(
                    "auth_excluded" if outcome == "excluded" else "auth_eligible", outcome
                )
                runtime.metrics.duration(operation, outcome, time.monotonic() - started)

        async def observed_send(message: Any) -> None:
            if message.get("type") == "http.response.start":
                status = message["status"]
                state = scope.get("state", {})
                authenticated = any(
                    key in state for key in ("saas_principal", "saas_machine_principal")
                )
                login_attempt = path == "/saas/auth/login" and scope.get("method") == "POST"
                if status < 400 and not (authenticated or login_attempt):
                    record("excluded")
                else:
                    record(
                        "failure" if status >= 500 else "excluded" if status >= 400 else "success"
                    )
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        finally:
            if not recorded:
                record("failure")
