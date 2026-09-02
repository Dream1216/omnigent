from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from saas.production.runner_agent import (
    ProductionRunnerAgent,
    load_production_runner_agent_config,
)
from saas.production.runner_control import (
    RunnerControlClientLease,
    RunnerControlError,
)

RUN_ID = UUID("10000000-0000-4000-8000-000000000001")
LEASE = RunnerControlClientLease(
    run_id=RUN_ID,
    lease_token=UUID("20000000-0000-4000-8000-000000000002"),
    fence_token=7,
    dispatch_generation=3,
    failure_domain="cn-east-1a",
    expires_at=datetime.now(timezone.utc) + timedelta(seconds=45),
    capability_id=UUID("30000000-0000-4000-8000-000000000003"),
    capability_token="cap_" + "c" * 60,
)


def test_agent_config_rejects_product_source_revision_drift() -> None:
    with pytest.raises(RunnerControlError, match="release identity"):
        load_production_runner_agent_config(
            {
                "OMNIGENT_SAAS_PRODUCT_REVISION": "a" * 40,
                "OMNIGENT_SAAS_SOURCE_SHA": "b" * 40,
                "OMNIGENT_SAAS_IMAGE_DIGEST": "sha256:" + "c" * 64,
            }
        )


class _Executor:
    def __init__(
        self,
        *,
        result: str = "succeeded",
        wait: bool = False,
        cancel_failure: bool = False,
        finalize_failure: bool = False,
    ) -> None:
        self.result = result
        self.wait = wait
        self.cancel_failure = cancel_failure
        self.finalize_failure = finalize_failure
        self.ready = 0
        self.claimable_checks = 0
        self.poisoned = False
        self.calls: list[RunnerControlClientLease] = []
        self.cancelled = False
        self.prepared: list[str] = []
        self.finalized: list[str] = []
        self.gc_limits: list[int] = []

    def assert_production_ready(self) -> None:
        self.ready += 1

    def bind_preview_runtime(self, supervisor: object) -> None:
        del supervisor

    def assert_claimable(self) -> None:
        self.claimable_checks += 1
        if self.poisoned:
            raise RunnerControlError(
                "runner_worktree_heartbeat_worker_poisoned",
                "Worktree heartbeat worker requires Runner restart",
            )

    async def execute(
        self,
        lease: RunnerControlClientLease,
        *,
        cancellation: asyncio.Event,
    ) -> str:
        self.calls.append(lease)
        if self.wait:
            try:
                await cancellation.wait()
                self.cancelled = True
            except asyncio.CancelledError:
                self.cancelled = cancellation.is_set()
                raise
        return self.result

    async def cancel(self, lease: RunnerControlClientLease) -> None:
        assert lease == LEASE
        self.cancelled = True
        if self.cancel_failure:
            raise RuntimeError("external executor cancellation failed")

    async def prepare_finalization(
        self,
        lease: RunnerControlClientLease,
        *,
        result: str,
    ) -> str:
        assert lease == LEASE
        self.prepared.append(result)
        return result

    async def prepare_terminal_transition(self, lease: RunnerControlClientLease) -> None:
        assert lease == LEASE

    async def finalize(self, lease: RunnerControlClientLease, *, result: str) -> None:
        assert lease == LEASE
        self.finalized.append(result)
        if self.finalize_failure:
            raise RuntimeError("executor finalize failed")

    async def reconcile_physical_gc(self, *, limit: int) -> int:
        self.gc_limits.append(limit)
        return 0


class _Client:
    def __init__(
        self,
        stop: asyncio.Event,
        *,
        heartbeat_failure: bool = False,
        cancel_after_heartbeat: bool = False,
        initial_status: str = "leased",
        release_failure: bool = False,
    ) -> None:
        self.stop = stop
        self.heartbeat_failure = heartbeat_failure
        self.cancel_after_heartbeat = cancel_after_heartbeat
        self.initial_status = initial_status
        self.release_failure = release_failure
        self.claimed = False
        self.runner_heartbeats = 0
        self.run_heartbeats = 0
        self.transitions: list[str] = []
        self.releases = 0

    async def heartbeat_runner(self) -> str:
        self.runner_heartbeats += 1
        return "online"

    async def claim_run(self) -> RunnerControlClientLease | None:
        if self.claimed:
            return None
        self.claimed = True
        return LEASE

    async def heartbeat_run(self, lease: RunnerControlClientLease) -> dict[str, object]:
        assert lease == LEASE
        self.run_heartbeats += 1
        if self.heartbeat_failure and self.run_heartbeats > 1:
            raise RunnerControlError(
                "runner_control_transport_unavailable", "Runner control is unavailable"
            )
        if self.cancel_after_heartbeat and self.run_heartbeats > 1:
            return {"status": "cancelling"}
        return {"status": self.initial_status if not self.transitions else self.transitions[-1]}

    async def transition_run(
        self,
        lease: RunnerControlClientLease,
        *,
        target_status: str,
    ) -> dict[str, object]:
        assert lease == LEASE
        self.transitions.append(target_status)
        return {"status": target_status}

    async def release_run(self, lease: RunnerControlClientLease) -> bool:
        assert lease == LEASE
        self.releases += 1
        if self.release_failure:
            raise RunnerControlError(
                "runner_control_transport_unavailable",
                "release result is unknown",
            )
        self.stop.set()
        return False


class _PreviewTunnel:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.ready = 0
        self.closed = 0

    def assert_production_ready(self) -> None:
        self.ready += 1

    async def run(self, stop: asyncio.Event) -> None:
        if self.failure is not None:
            raise self.failure
        await stop.wait()

    async def aclose(self) -> None:
        self.closed += 1


class _IdleClient(_Client):
    async def claim_run(self) -> RunnerControlClientLease | None:
        return None


@pytest.mark.asyncio
async def test_agent_claims_executes_transitions_and_releases_one_terminal_lease() -> None:
    stop = asyncio.Event()
    client = _Client(stop)
    executor = _Executor(result="succeeded")
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    stats = await agent.run(stop)

    assert executor.ready == 1
    assert executor.calls == [LEASE]
    assert executor.prepared == ["succeeded"]
    assert executor.finalized == ["succeeded"]
    assert client.transitions == ["starting", "running", "succeeded"]
    assert client.releases == 1
    assert client.runner_heartbeats == 2
    assert stats.claims == stats.completed == stats.released == 1
    assert stats.failed == 0


@pytest.mark.asyncio
async def test_run_heartbeat_remains_live_during_terminal_preparation() -> None:
    stop = asyncio.Event()
    finalization_heartbeat = asyncio.Event()

    class _FinalizationClient(_Client):
        async def heartbeat_run(self, lease: RunnerControlClientLease) -> dict[str, object]:
            state = await super().heartbeat_run(lease)
            if self.run_heartbeats >= 2:
                finalization_heartbeat.set()
            return state

    class _WaitingFinalizationExecutor(_Executor):
        async def prepare_finalization(
            self,
            lease: RunnerControlClientLease,
            *,
            result: str,
        ) -> str:
            await asyncio.wait_for(finalization_heartbeat.wait(), timeout=1)
            return await super().prepare_finalization(lease, result=result)

    client = _FinalizationClient(stop)
    executor = _WaitingFinalizationExecutor()
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]
    agent._heartbeat_interval = 0.01

    stats = await asyncio.wait_for(agent.run(stop), timeout=2)

    assert client.run_heartbeats >= 2
    assert executor.prepared == ["succeeded"]
    assert stats.completed == stats.released == 1


@pytest.mark.asyncio
async def test_poisoned_executor_exits_before_claiming_another_run() -> None:
    stop = asyncio.Event()

    class _GreedyClient(_Client):
        def __init__(self) -> None:
            super().__init__(stop)
            self.claim_attempts = 0

        async def claim_run(self) -> RunnerControlClientLease:
            self.claim_attempts += 1
            return LEASE

        async def release_run(self, lease: RunnerControlClientLease) -> bool:
            assert lease == LEASE
            self.releases += 1
            return False

    class _PoisonAfterFirstRun(_Executor):
        async def execute(
            self,
            lease: RunnerControlClientLease,
            *,
            cancellation: asyncio.Event,
        ) -> str:
            result = await super().execute(lease, cancellation=cancellation)
            self.poisoned = True
            return result

    client = _GreedyClient()
    executor = _PoisonAfterFirstRun(result="failed")
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    with pytest.raises(RunnerControlError) as poisoned:
        await agent.run(stop)

    assert poisoned.value.code == "runner_worktree_heartbeat_worker_poisoned"
    assert client.claim_attempts == 1
    assert executor.calls == [LEASE]
    assert client.releases == 1
    assert executor.claimable_checks == 2


@pytest.mark.asyncio
async def test_database_authority_drift_exits_before_claiming_another_run() -> None:
    stop = asyncio.Event()

    class _GreedyClient(_Client):
        def __init__(self) -> None:
            super().__init__(stop)
            self.claim_attempts = 0

        async def claim_run(self) -> RunnerControlClientLease:
            self.claim_attempts += 1
            return LEASE

        async def release_run(self, lease: RunnerControlClientLease) -> bool:
            assert lease == LEASE
            self.releases += 1
            return False

    class _DatabaseDriftAfterFirstRun(_Executor):
        def assert_claimable(self) -> None:
            self.claimable_checks += 1
            if self.poisoned:
                raise RunnerControlError(
                    "runner_database_authority_drifted",
                    "Runner database authority changed after startup",
                )

        async def execute(
            self,
            lease: RunnerControlClientLease,
            *,
            cancellation: asyncio.Event,
        ) -> str:
            result = await super().execute(lease, cancellation=cancellation)
            self.poisoned = True
            return result

    client = _GreedyClient()
    executor = _DatabaseDriftAfterFirstRun(result="failed")
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    with pytest.raises(RunnerControlError) as drifted:
        await agent.run(stop)

    assert drifted.value.code == "runner_database_authority_drifted"
    assert client.claim_attempts == 1
    assert executor.calls == [LEASE]
    assert client.releases == 1
    assert executor.claimable_checks == 2


@pytest.mark.asyncio
async def test_preview_tunnel_failure_stops_claim_loop_and_fails_agent_closed() -> None:
    stop = asyncio.Event()
    client = _IdleClient(stop)
    executor = _Executor()
    preview = _PreviewTunnel(failure=RuntimeError("preview disconnected"))
    agent = ProductionRunnerAgent(
        client,
        executor,
        poll_interval_seconds=0.05,
        preview_tunnel=preview,
    )  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="preview disconnected"):
        await agent.run(stop)

    assert stop.is_set()
    assert preview.ready == 1
    assert preview.closed == 1
    assert executor.ready == 1


@pytest.mark.asyncio
async def test_heartbeat_failure_aborts_runtime_without_replaying_terminal_mutations() -> None:
    stop = asyncio.Event()
    client = _Client(stop, heartbeat_failure=True)
    executor = _Executor(wait=True)
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]
    agent._heartbeat_interval = 0.01

    with pytest.raises(RunnerControlError) as unavailable:
        await agent.run(stop)

    assert unavailable.value.code == "runner_control_transport_unavailable"
    assert executor.cancelled
    assert client.transitions == ["starting", "running"]
    assert client.releases == 0
    assert client.run_heartbeats == 2


@pytest.mark.asyncio
async def test_unrecognized_executor_result_fails_closed_before_release() -> None:
    stop = asyncio.Event()
    client = _Client(stop)
    executor = _Executor(result="pretend-success")
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    stats = await agent.run(stop)

    assert client.transitions == ["starting", "running", "failed"]
    assert stats.failed == 1
    assert stats.completed == 0


@pytest.mark.asyncio
async def test_durable_external_cancellation_stops_executor_then_releases_cancelled() -> None:
    stop = asyncio.Event()
    client = _Client(stop, cancel_after_heartbeat=True)
    executor = _Executor(result="cancelled", wait=True)
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]
    agent._heartbeat_interval = 0.01

    stats = await agent.run(stop)

    assert executor.cancelled
    assert executor.finalized == ["cancelled"]
    assert executor.prepared == ["cancelled"]
    assert client.transitions == ["starting", "running", "cancelled"]
    assert client.releases == 1
    assert stats.failed == stats.released == 1


@pytest.mark.asyncio
async def test_failed_external_cancellation_is_orphaned_before_release() -> None:
    stop = asyncio.Event()
    client = _Client(stop, cancel_after_heartbeat=True)
    executor = _Executor(wait=True, cancel_failure=True)
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]
    agent._heartbeat_interval = 0.01

    stats = await agent.run(stop)

    assert executor.finalized == ["orphaned"]
    assert executor.prepared == ["orphaned"]
    assert client.transitions == ["starting", "running", "orphaned"]
    assert client.releases == 1
    assert stats.failed == stats.released == 1


@pytest.mark.asyncio
async def test_already_cancelling_claim_never_starts_executor() -> None:
    stop = asyncio.Event()
    client = _Client(stop, initial_status="cancelling")
    executor = _Executor(wait=True)
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    stats = await agent.run(stop)

    assert executor.calls == []
    assert executor.prepared == []
    assert executor.finalized == ["cancelled"]
    assert client.transitions == ["cancelled"]
    assert client.releases == 1
    assert stats.failed == stats.released == 1


@pytest.mark.asyncio
async def test_finalize_failure_does_not_replay_terminal_or_attempt_dispatch_release() -> None:
    stop = asyncio.Event()
    client = _Client(stop)
    executor = _Executor(finalize_failure=True)
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    with pytest.raises(RuntimeError, match="executor finalize failed"):
        await agent._execute_lease(LEASE, stop)

    assert executor.prepared == ["succeeded"]
    assert executor.finalized == ["succeeded"]
    assert client.transitions == ["starting", "running", "succeeded"]
    assert client.releases == 0


@pytest.mark.asyncio
async def test_unknown_dispatch_release_result_is_never_replayed() -> None:
    stop = asyncio.Event()
    client = _Client(stop, release_failure=True)
    executor = _Executor()
    agent = ProductionRunnerAgent(client, executor)  # type: ignore[arg-type]

    with pytest.raises(RunnerControlError) as unavailable:
        await agent._execute_lease(LEASE, stop)

    assert unavailable.value.code == "runner_control_transport_unavailable"
    assert executor.prepared == ["succeeded"]
    assert executor.finalized == ["succeeded"]
    assert client.transitions == ["starting", "running", "succeeded"]
    assert client.releases == 1
