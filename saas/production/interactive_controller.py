"""Interactive execution adapter for the existing fenced Runner agent loop."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import UUID

import httpx

from omnigent.host.frames import HostLaunchRunnerFrame
from saas.compatibility import RuntimeContext
from saas.control_plane.interactive_run_route import interactive_session_identity
from saas.production.interactive_model_channel import (
    HostModelChannel,
    ModelChannelScope,
    SessionModelChannels,
    host_model_channel,
    prepare_host_model_channel,
)
from saas.production.interactive_recovery import (
    InteractiveCleanupRecord,
    InteractiveRecoveryJournal,
    InteractiveRecoveryRecord,
    ManagedCreationIntent,
    ManagedPreparationBinding,
    ManagedResourceBinding,
    ManagedTerminationReceipt,
    UnstartedInteractiveRecoveryRecord,
    certificate_sha256,
    managed_retirement_proof_sha256,
)
from saas.production.interactive_runtime import AuthorizedInteractiveInput
from saas.production.model_run_credentials import IssuedModelRunCredential
from saas.production.platform_model_relay import PlatformModelRelay
from saas.production.runner_control import RunnerControlClientLease, RunnerControlError
from saas.runner_adapter.metering import (
    ManagedMeteringGrant,
    ProviderUsageMeter,
    build_metering_client,
)


class InteractivePhysicalDriver(Protocol):
    def assert_production_ready(self) -> None: ...

    async def revalidate_managed(
        self, authorized, origins, *, previous=None
    ) -> InteractiveRecoveryRecord | None: ...

    async def prepare(
        self,
        authorized: AuthorizedInteractiveInput,
        *,
        previous: InteractiveRecoveryRecord | None,
        on_launch: Callable[[HostLaunchRunnerFrame, object], Awaitable[HostLaunchRunnerFrame]],
        on_preparation: Callable[[ManagedPreparationBinding], Awaitable[None]],
        on_resources: Callable[[ManagedResourceBinding], Awaitable[None]],
        on_creation: Callable[[ManagedCreationIntent], Awaitable[None]],
    ) -> object: ...

    async def dispatch(self, authorized: AuthorizedInteractiveInput, handle: object) -> None: ...

    async def outcome(self, authorized: AuthorizedInteractiveInput, handle: object) -> str: ...

    async def stop(self, record: InteractiveRecoveryRecord) -> bool: ...

    async def recover_managed(self, record, checkpoint) -> InteractiveRecoveryRecord: ...

    async def inspect_managed_retirement(self, record, *, cutoff, now, force=False): ...

    async def detach_managed_retirement(self, record, host) -> bool: ...

    async def retire_managed(self, record, checkpoint) -> InteractiveRecoveryRecord: ...

    async def finish_managed_retirement(self, record) -> bool: ...

    async def shutdown_managed(self) -> None: ...

    async def quiesce_preparation(self, authorized: AuthorizedInteractiveInput) -> None: ...

    async def release(self, handle: object) -> None: ...


@dataclass(slots=True)
class _Active:
    authorized: AuthorizedInteractiveInput
    lease: RunnerControlClientLease
    record: InteractiveRecoveryRecord
    meter: ProviderUsageMeter = field(repr=False)
    cancellation: asyncio.Event = field(repr=False)
    preparation: asyncio.Task | None = field(default=None, repr=False)
    dispatching: asyncio.Task | None = field(default=None, repr=False)
    handle: object | None = None
    bound: bool = False
    drained: bool = False
    stopped: bool = False
    executing: bool = False
    cancellation_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    finished: asyncio.Event = field(default_factory=asyncio.Event, repr=False)


def _unavailable() -> RunnerControlError:
    return RunnerControlError(
        "interactive_controller_unavailable", "Interactive execution is unavailable"
    )


class ProductionInteractiveExecutor:
    """Own model/physical barriers, leaving the lease lifecycle in RunnerAgent."""

    def __init__(
        self,
        *,
        authorize_model: Callable[
            [RunnerControlClientLease],
            Awaitable[tuple[AuthorizedInteractiveInput, IssuedModelRunCredential]],
        ],
        grant_for_run: Callable[
            [AuthorizedInteractiveInput, RunnerControlClientLease], ManagedMeteringGrant
        ],
        driver: InteractivePhysicalDriver,
        journal: InteractiveRecoveryJournal,
        recovery_certificate_path: Path,
        channels: SessionModelChannels,
        connection_generation: int,
        product_revision: str,
        image_digest: str,
        assert_authority: Callable[[], None],
        verify_recovery: Callable[[InteractiveCleanupRecord], Awaitable[None]],
        confirm_recovery: Callable[[InteractiveCleanupRecord], Awaitable[None]],
        verify_released: Callable[[InteractiveRecoveryRecord], Awaitable[None]] | None = None,
        inspect_revocation: Callable[[InteractiveRecoveryRecord], Awaitable[bool]] | None = None,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        meter_factory: Callable[[ManagedMeteringGrant], ProviderUsageMeter] | None = None,
    ):
        self._authorize, self._grant = authorize_model, grant_for_run
        self._driver, self._journal, self._channels = driver, journal, channels
        self._recovery_certificate_path = recovery_certificate_path
        self._generation, self._revision, self._image = (
            connection_generation,
            product_revision,
            image_digest,
        )
        self._assert_authority, self._verify_recovery = assert_authority, verify_recovery
        self._confirm_recovery = confirm_recovery
        self._verify_released = verify_released
        self._inspect_revocation = inspect_revocation
        self._client_factory = client_factory
        self._meter_factory = meter_factory or (
            lambda grant: ProviderUsageMeter(
                grant=grant, client=build_metering_client(grant), gateway_managed=True
            )
        )
        self._active: dict[UUID, _Active] = {}
        self._retirements: dict[UUID, asyncio.Task[bool]] = {}
        self._completed_retirements: set[UUID] = set()
        self._recovering = asyncio.Lock()
        self._confirmed_recoveries: set[UUID] = set()
        self._gc_offset = 0
        self._closing = False
        self._lifecycle = asyncio.Lock()

    def assert_production_ready(self) -> None:
        self._assert_authority()
        self._driver.assert_production_ready()

    def assert_claimable(self) -> None:
        self.assert_production_ready()
        if any(record.phase != "terminal" for record in self._journal.records()):
            raise RunnerControlError(
                "interactive_controller_recovery_pending",
                "Interactive execution is unavailable until recovery completes",
            )

    def bind_preview_runtime(self, supervisor: object) -> None:
        del supervisor
        raise _unavailable()

    def _put(self, active: _Active, **changes) -> None:
        updated = replace(active.record, updated_at=datetime.now(timezone.utc), **changes)
        self._journal.put(updated)
        active.record = updated

    async def _bind(self, active: _Active, channel: HostModelChannel) -> None:
        async def renew():
            current, issued = await self._authorize(active.lease)
            if (
                current.run_id != active.authorized.run_id
                or current.fence_token != active.authorized.fence_token
                or current.session_id != active.authorized.session_id
                or current.publication != active.authorized.publication
                or current.launch != active.authorized.launch
                or current.runtime.actor_id != active.authorized.runtime.actor_id
            ):
                raise _unavailable()
            return issued

        relay = PlatformModelRelay.for_run(
            run_id=active.lease.run_id,
            fence_token=active.lease.fence_token,
            credential_provider=renew,
            capability=channel.secret_value,
            metering=active.meter,
            client_factory=self._client_factory,
        )
        await self._channels.bind(
            active.record.scope,
            secret_value=channel.secret_value,
            run_id=active.lease.run_id,
            fence_token=active.lease.fence_token,
            relay=relay,
            accepting=False,
        )
        active.bound = True

    async def _prepare_active(
        self, lease: RunnerControlClientLease, *, cancellation: asyncio.Event
    ) -> tuple[_Active, InteractiveRecoveryRecord | None]:
        if (
            lease.run_id in self._active
            or lease.execution_envelope is None
            or lease.execution_envelope.execution_kind != "omnigent.interactive.v1"
        ):
            raise _unavailable()
        authorized, _issued = await self._authorize(lease)
        grant = self._grant(authorized, lease)
        if (
            grant.run_id != lease.run_id
            or not hmac.compare_digest(grant.capability_token, lease.capability_token)
            or grant.model_budget_reservation_id is not None
            or authorized.runtime.project_id is None
            or grant.runner_id != lease.execution_envelope.runner_id
            or grant.session_id
            != interactive_session_identity(
                authorized.runtime.tenant_id,
                authorized.runtime.space_id,
                authorized.runtime.runtime_partition_id,
                authorized.session_id,
            )
        ):
            raise _unavailable()
        scope = ModelChannelScope(
            authorized.runtime.tenant_id,
            authorized.runtime.space_id,
            authorized.runtime.project_id,
            authorized.runtime.actor_id,
            grant.session_id,
            authorized.runtime.runtime_partition_id,
            authorized.session_id,
            str(authorized.publication["snapshot_sha256"]),
        )
        records = [
            row for row in self._journal.records() if row.scope.session_id == scope.session_id
        ]
        previous = max(records, key=lambda row: row.updated_at) if records else None
        if previous is not None and previous.process_stopped:
            previous = None
        if any(row.phase != "terminal" for row in records) or (
            previous is not None
            and (
                replace(previous.scope, actor_id=scope.actor_id) != scope
                or previous.channel_value is None
            )
        ):
            raise _unavailable()
        record = InteractiveRecoveryRecord(
            lease.run_id,
            lease.fence_token,
            self._generation,
            self._revision,
            self._image,
            scope,
            authorized.runtime,
            grant,
            certificate_sha256(grant),
            channel_value=previous.channel_value if previous else None,
            host_id=previous.host_id if previous else None,
            official_runner_id=previous.official_runner_id if previous else None,
            host_owner=previous.host_owner if previous else None,
            host_account_generation=previous.host_account_generation if previous else None,
        )
        self._journal.put(record)
        active = _Active(authorized, lease, record, self._meter_factory(grant), cancellation)
        self._active[lease.run_id] = active
        return active, previous

    async def execute(
        self, lease: RunnerControlClientLease, *, cancellation: asyncio.Event
    ) -> str:
        async with self._lifecycle:
            try:
                active, previous = await self._prepare_active(lease, cancellation=cancellation)
            except (Exception, asyncio.CancelledError):
                self._retain_unstarted(lease)
                raise
            active.executing = True
        authorized, scope = active.authorized, active.record.scope
        managed_origin: InteractiveRecoveryRecord | None = None
        preflight_complete = False

        async def launch(frame: HostLaunchRunnerFrame, connection) -> HostLaunchRunnerFrame:
            if active.bound or cancellation.is_set():
                raise _unavailable()
            if managed_origin is not None and (
                managed_origin.managed_preparation is None
                or self._journal.read(managed_origin.run_id) != managed_origin
                or (connection.host_id, connection.owner, connection.account_generation)
                != (
                    managed_origin.managed_preparation.host_id,
                    managed_origin.host_owner,
                    managed_origin.host_account_generation,
                )
            ):
                raise _unavailable()
            preparation = active.record.managed_preparation
            if preparation is not None and (
                active.record.managed_resources is None
                or connection.host_id != preparation.host_id
                or connection.owner != authorized.runtime.runtime_user_key
            ):
                raise _unavailable()
            channel = host_model_channel(
                frame, scope=scope, public_origin=self._channels.public_origin
            )
            from omnigent.runner.identity import token_bound_runner_id

            self._put(
                active,
                phase="launching",
                channel_value=channel.secret_value,
                host_id=connection.host_id,
                official_runner_id=token_bound_runner_id(frame.binding_token),
                host_owner=connection.owner,
                host_account_generation=connection.account_generation,
            )
            await self._bind(active, channel)
            return prepare_host_model_channel(frame, channel=channel)

        async def preparing(binding: ManagedPreparationBinding) -> None:
            if (
                self._active.get(lease.run_id) is not active
                or active.record.phase != "preparing"
                or active.record.managed_preparation is not None
                or active.record.process_stopped
                or active.record.official_runner_id is not None
                or authorized.launch["host_type"] != "managed"
                or binding.provider != authorized.launch["sandbox_provider"]
            ):
                raise _unavailable()
            self._put(active, managed_preparation=binding)

        async def resources(binding: ManagedResourceBinding) -> None:
            if (
                self._active.get(lease.run_id) is not active
                or active.record.phase != "preparing"
                or active.record.process_stopped
                or active.record.official_runner_id is not None
                or active.record.managed_preparation is None
                or authorized.launch["host_type"] != "managed"
            ):
                raise _unavailable()
            self._put(active, managed_resources=binding)

        async def creation(intent: ManagedCreationIntent) -> None:
            if (
                self._active.get(lease.run_id) is not active
                or active.record.phase != "preparing"
                or active.record.process_stopped
                or active.record.official_runner_id is not None
                or active.record.managed_preparation is None
                or authorized.launch["host_type"] != "managed"
            ):
                raise _unavailable()
            self._put(active, managed_creation=intent)

        try:
            if authorized.launch["host_type"] == "managed":
                origins = tuple(
                    row
                    for row in self._journal.records()
                    if replace(row.scope, actor_id=scope.actor_id) == scope
                    and row.managed_origin_run_id is None
                    and row.managed_preparation is not None
                    and row.managed_creation is not None
                    and row.managed_resources is not None
                    and row.host_id == row.managed_preparation.host_id
                    and row.host_owner is not None
                    and row.official_runner_id is not None
                )
                if previous is not None:
                    origins = tuple(
                        row
                        for row in origins
                        if row.managed_preparation is not None
                        and row.managed_preparation.host_id == previous.host_id
                        and (
                            previous.managed_origin_run_id is None
                            or row.run_id == previous.managed_origin_run_id
                        )
                    )
                    if len(origins) != 1 or origins[0].managed_termination is not None:
                        raise _unavailable()
                managed_origin = await self._driver.revalidate_managed(
                    authorized, origins, previous=previous
                )
                if managed_origin is not None:
                    if managed_origin not in origins or self._verify_released is None:
                        raise _unavailable()
                    await self._verify_recovery(managed_origin)
                    await self._verify_released(managed_origin)
                elif previous is not None:
                    raise _unavailable()
            async with self._lifecycle:
                if cancellation.is_set():
                    await self.cancel(lease)
                    return "cancelled" if active.stopped else "orphaned"
                if (
                    self._closing
                    or self._active.get(lease.run_id) is not active
                    or active.record.process_stopped
                    or active.record.phase != "prepared"
                ):
                    raise _unavailable()
                if managed_origin is not None:
                    if (
                        self._journal.read(managed_origin.run_id) != managed_origin
                        or managed_origin.managed_termination is not None
                    ):
                        raise _unavailable()
                    self._put(active, managed_origin_run_id=managed_origin.run_id)
                preflight_complete = True
                if previous is not None:
                    assert previous.channel_value is not None
                    self._put(
                        active,
                        channel_value=previous.channel_value,
                        host_id=previous.host_id,
                        official_runner_id=previous.official_runner_id,
                        host_owner=previous.host_owner,
                        host_account_generation=previous.host_account_generation,
                    )
                    await self._bind(
                        active,
                        HostModelChannel(
                            authorized.session_id,
                            self._channels.restore(scope, previous.channel_value).base_url,
                            previous.channel_value,
                        ),
                    )
                self._put(active, phase="preparing")
                active.preparation = asyncio.create_task(
                    self._driver.prepare(
                        authorized,
                        previous=previous,
                        on_launch=launch,
                        on_preparation=preparing,
                        on_resources=resources,
                        on_creation=creation,
                    ),
                    name="interactive-prepare",
                )
            try:
                active.handle = await active.preparation
            except asyncio.CancelledError:
                task = asyncio.current_task()
                if not cancellation.is_set() or (task is not None and task.cancelling()):
                    raise
                await self.cancel(lease)
                return "cancelled" if active.stopped else "orphaned"
            async with self._lifecycle:
                if cancellation.is_set():
                    return "cancelled" if active.stopped else "orphaned"
                if not active.bound:
                    return "failed"
                await self._authorize(lease)
                self._put(active, phase="dispatching")
                await self._channels.activate(
                    scope.session_id, run_id=lease.run_id, fence_token=lease.fence_token
                )
                active.dispatching = asyncio.create_task(
                    self._driver.dispatch(authorized, active.handle), name="interactive-dispatch"
                )
            try:
                await active.dispatching
            except asyncio.CancelledError:
                task = asyncio.current_task()
                if not cancellation.is_set() or (task is not None and task.cancelling()):
                    raise
                await self.cancel(lease)
                return "cancelled" if active.stopped else "orphaned"
            result = asyncio.create_task(self._driver.outcome(authorized, active.handle))
            cancelled = asyncio.create_task(cancellation.wait())
            try:
                done, _ = await asyncio.wait(
                    {result, cancelled}, return_when=asyncio.FIRST_COMPLETED
                )
                if cancelled in done:
                    await self.cancel(lease)
                    return "cancelled" if active.stopped else "orphaned"
                outcome = await result
                if outcome not in {"succeeded", "failed", "cancelled"}:
                    return "orphaned"
                async with self._lifecycle:
                    if cancellation.is_set():
                        return "cancelled" if active.stopped else "orphaned"
                    self._put(active, phase="draining", outcome=outcome)
                return outcome
            finally:
                for task in (result, cancelled):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(result, cancelled, return_exceptions=True)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - do not expose transport or credential diagnostics.
            if not preflight_complete and cancellation.is_set():
                await self.cancel(lease)
                return "cancelled" if active.stopped else "orphaned"
            self._put(
                active,
                phase="draining" if preflight_complete else active.record.phase,
                outcome="failed",
            )
            raise _unavailable() from None
        finally:
            active.executing = False

    def _retain_unstarted(self, lease: RunnerControlClientLease) -> None:
        if lease.run_id in self._active:
            return
        envelope = lease.execution_envelope
        if (
            envelope is None
            or envelope.execution_kind != "omnigent.interactive.v1"
            or envelope.run_id != lease.run_id
            or envelope.fence_token != lease.fence_token
            or envelope.product_revision != self._revision
            or envelope.image_digest != self._image
        ):
            raise _unavailable()
        self._journal.retain_unstarted(
            UnstartedInteractiveRecoveryRecord(
                run_id=lease.run_id,
                runner_id=envelope.runner_id,
                fence_token=lease.fence_token,
                connection_generation=self._generation,
                product_revision=self._revision,
                image_digest=self._image,
                capability_token=lease.capability_token,
                certificate_sha256=sha256(
                    self._recovery_certificate_path.read_bytes()
                ).hexdigest(),
            )
        )

    async def _seal(self, active: _Active, *, timeout: float = 10) -> bool:
        if active.bound:
            active.drained = await self._channels.suspend(
                active.record.scope.session_id,
                run_id=active.lease.run_id,
                fence_token=active.lease.fence_token,
                timeout=timeout,
            )
        else:
            active.drained = True
        return active.drained

    async def stop_session(
        self,
        runtime: RuntimeContext,
        session_id: str,
        runner_id: str | None,
        cancel_inputs: Callable[[], Awaitable[dict[str, bool | str]]],
    ) -> dict[str, bool | str]:
        deadline = asyncio.get_running_loop().time() + 10
        while True:
            async with self._lifecycle:
                records = [
                    row
                    for row in self._journal.records()
                    if row.scope.tenant_id == runtime.tenant_id
                    and row.scope.space_id == runtime.space_id
                    and row.scope.partition_id == runtime.runtime_partition_id
                    and row.scope.official_session_id == session_id
                    and row.runtime.physical_workspace_id == runtime.physical_workspace_id
                ]
                active = [
                    self._active[row.run_id] for row in records if row.run_id in self._active
                ]
                finishing = [
                    row.finished
                    for row in active
                    if row.record.phase == "draining" and not row.finished.is_set()
                ]
                if not finishing:
                    return await self._stop_owned_session(
                        records, active, runner_id, cancel_inputs
                    )
            try:
                # Preserve an observed completed turn; stop its idle Runner after finalization.
                await asyncio.wait_for(
                    asyncio.gather(*(event.wait() for event in finishing)),
                    max(0, deadline - asyncio.get_running_loop().time()),
                )
            except TimeoutError:
                raise _unavailable() from None

    async def _stop_owned_session(
        self, records, active, runner_id, cancel_inputs
    ) -> dict[str, bool | str]:
        self.assert_production_ready()
        control = await cancel_inputs()
        if control.get("physical_run_id") and not any(
            str(row.run_id) == control["physical_run_id"] for row in records
        ):
            raise _unavailable()
        if any(row.phase != "terminal" and row.run_id not in self._active for row in records):
            raise _unavailable()
        if active:
            for current in active:
                current.cancellation.set()
                await self.cancel(current.lease)
                if not current.stopped:
                    raise _unavailable()
        else:
            latest = max(records, key=lambda row: row.updated_at) if records else None
            if latest is None:
                if runner_id is not None:
                    raise _unavailable()
            else:
                if runner_id is not None and runner_id != latest.official_runner_id:
                    raise _unavailable()
                if not latest.process_stopped:
                    await self._verify_recovery(latest)
                    if not await self._driver.stop(latest):
                        raise _unavailable()
                    self._journal.put(
                        replace(
                            latest, process_stopped=True, updated_at=datetime.now(timezone.utc)
                        )
                    )
                    await self._channels.forget(latest.scope.session_id)
        return {"queued": False}

    async def cancel(self, lease: RunnerControlClientLease) -> None:
        active = self._active.get(lease.run_id)
        if active is None:
            return
        async with active.cancellation_lock:
            active.cancellation.set()
            if active.stopped:
                return
            if active.preparation is not None and not active.preparation.done():
                active.preparation.cancel()
                await asyncio.gather(active.preparation, return_exceptions=True)
            await self._driver.quiesce_preparation(active.authorized)
            # Fence new inference before stopping; finalization drains existing requests.
            await self._seal(active, timeout=0)
            never_started = (
                active.record.phase == "prepared"
                and active.preparation is None
                and active.record.official_runner_id is None
            )
            active.stopped = (
                active.record.process_stopped
                or never_started
                or await self._driver.stop(active.record)
            )
            if active.stopped:
                self._put(
                    active,
                    process_stopped=True,
                    stop_kind="never_started" if never_started else active.record.stop_kind,
                )
            if active.dispatching is not None and not active.dispatching.done():
                active.dispatching.cancel()
                await asyncio.gather(active.dispatching, return_exceptions=True)

    async def prepare_finalization(self, lease: RunnerControlClientLease, *, result: str) -> str:
        active = self._active.get(lease.run_id)
        if active is None:
            return result
        await self._seal(active)
        if result != "succeeded" or active.record.outcome != "succeeded":
            await self.cancel(lease)
            if not active.stopped:
                return "orphaned"
        await asyncio.to_thread(active.meter.close, 0)
        return result if active.drained else "orphaned"

    async def prepare_terminal_transition(self, lease: RunnerControlClientLease) -> None:
        active = self._active.get(lease.run_id)
        if active is not None and not active.drained:
            raise _unavailable()

    async def finalize(self, lease: RunnerControlClientLease, *, result: str) -> None:
        async with self._lifecycle:
            await self._finalize(lease, result=result)

    async def _finalize(self, lease: RunnerControlClientLease, *, result: str) -> None:
        active = self._active.get(lease.run_id)
        if active is None:
            return
        if not active.drained:
            raise _unavailable()
        if not active.stopped and result == "orphaned":
            self._put(active, phase="draining", outcome="orphaned")
            active.finished.set()
            return
        if result != "succeeded" and not active.stopped:
            raise _unavailable()
        self._put(active, phase="terminal", outcome=result, process_stopped=active.stopped)
        if active.handle is not None:
            await self._driver.release(active.handle)
        if active.stopped:
            await self._channels.forget(active.record.scope.session_id)
        active.finished.set()
        del self._active[lease.run_id]

    async def _retire_orphaned(self, record: InteractiveRecoveryRecord) -> bool:
        async with self._lifecycle:
            active = self._active.get(record.run_id)
            if active is None:
                return True
            if (
                self._verify_released is None
                or active.record != record
                or not (
                    record.phase == "draining"
                    or (record.phase == "terminal" and record.process_stopped)
                )
                or record.outcome != "orphaned"
                or not active.finished.is_set()
                or active.executing
                or any(
                    task is not None and not task.done()
                    for task in (active.preparation, active.dispatching)
                )
            ):
                return False
            if (
                record.connection_generation != self._generation
                or record.product_revision != self._revision
                or record.image_digest != self._image
                or certificate_sha256(record.grant) != record.certificate_sha256
            ):
                raise _unavailable()
            await self._verify_recovery(record)
            try:
                await self._verify_released(record)
            except RunnerControlError as error:
                if error.code == "interactive_controller_recovery_pending":
                    return False
                raise
            if not await self._seal(active):
                return False
            await self._driver.quiesce_preparation(active.authorized)
            await asyncio.to_thread(active.meter.close, 0)
            if active.handle is not None:
                await self._driver.release(active.handle)
            if (
                self._active.get(record.run_id) is not active
                or self._journal.read(record.run_id) != record
            ):
                return False
            # Retain durable unknown-stop facts; ordinary recovery must still obtain an ACK.
            del self._active[record.run_id]
            return True

    def _managed_peers(self, record):
        origin = (
            self._journal.read(record.managed_origin_run_id)
            if record.managed_origin_run_id is not None
            else record
        )
        if not isinstance(origin, InteractiveRecoveryRecord):
            raise _unavailable()
        if origin.managed_preparation is None:
            return []
        host = origin.managed_preparation.host_id
        return [
            row
            for row in self._journal.records()
            if row.run_id != record.run_id
            and (
                row.run_id == origin.run_id
                or row.managed_origin_run_id == origin.run_id
                or row.host_id == host
                or (
                    row.managed_preparation is not None and row.managed_preparation.host_id == host
                )
                or (
                    record.managed_resources is not None
                    and row.managed_resources is not None
                    and record.managed_resources.workload_uid == row.managed_resources.workload_uid
                )
            )
        ]

    async def retire_managed_origin(
        self, run_id: UUID, *, cutoff: int, now: int, force: bool = False
    ) -> bool:
        async with self._lifecycle:
            if self._closing or run_id in self._completed_retirements:
                return False
            operation = self._retirements.get(run_id)
            if operation is None:
                operation = asyncio.create_task(
                    self._retire_managed_origin(run_id, cutoff=cutoff, now=now, force=force),
                    name="interactive-managed-retirement",
                )
                self._retirements[run_id] = operation

                def finished(task):
                    if self._retirements.get(run_id) is task:
                        del self._retirements[run_id]
                    if not task.cancelled():
                        task.exception()

                operation.add_done_callback(finished)
        try:
            return await asyncio.shield(operation)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - redact database and provider diagnostics.
            raise _unavailable() from None

    async def _retire_managed_origin(self, run_id, *, cutoff, now, force):
        async with self._recovering:
            return await self._retire_managed_origin_locked(
                run_id, cutoff=cutoff, now=now, force=force
            )

    async def _retire_managed_origin_locked(self, run_id, *, cutoff, now, force):
        if self._verify_released is None:
            return False
        origin = self._journal.read(run_id)
        if (
            origin.managed_origin_run_id is not None
            or origin.managed_preparation is None
            or origin.managed_creation is None
            or origin.managed_resources is None
        ):
            return False
        creation = origin.managed_creation
        peers = tuple(self._managed_peers(origin))

        def parked(row):
            active = self._active.get(row.run_id)
            return active is None or (
                active.record == row
                and not active.executing
                and active.finished.is_set()
                and (row.phase == "draining" or (row.phase == "terminal" and row.process_stopped))
                and row.outcome == "orphaned"
            )

        if not all(parked(row) for row in (origin, *peers)):
            return False
        if any(
            row.managed_origin_run_id not in (None, origin.run_id)
            or (
                row.managed_preparation is not None
                and row.managed_resources != origin.managed_resources
            )
            or (not row.process_stopped and row.managed_origin_run_id != origin.run_id)
            for row in peers
        ):
            return False
        host = await self._driver.inspect_managed_retirement(
            origin,
            cutoff=cutoff,
            now=now,
            force=force or any(row.outcome == "orphaned" for row in (origin, *peers)),
        )
        if host is None:
            return False
        for row in (origin, *peers):
            await self._verify_recovery(row)
            await self._verify_released(row)

        expected = origin

        def unchanged():
            return (
                not self._closing
                and self._journal.read(run_id) == expected
                and tuple(self._managed_peers(expected)) == peers
                and all(parked(row) for row in (expected, *peers))
            )

        async with self._lifecycle:
            if not unchanged():
                return False
            for row in (expected, *peers):
                active = self._active.get(row.run_id)
                if active is not None:
                    await self._seal(active, timeout=0)
                    await self._driver.quiesce_preparation(active.authorized)
            if not unchanged():
                return False
            # Hold admission through the credential-generation CAS. A stale
            # heartbeat loser must not leave an irreversible private stop intent.
            if not await self._driver.detach_managed_retirement(expected, host):
                return False
            if expected.managed_termination is None or expected.phase != "terminal":
                expected = replace(
                    expected,
                    phase=expected.phase if expected.phase == "terminal" else "draining",
                    outcome=expected.outcome if expected.phase == "terminal" else "orphaned",
                    managed_termination=expected.managed_termination
                    or ManagedTerminationReceipt(secret_uid=creation.secret_uid),
                )
                self._journal.put(expected)
                if run_id in self._active:
                    self._active[run_id].record = expected

        async def checkpoint(**changes):
            nonlocal expected
            async with self._lifecycle:
                if not unchanged() or set(changes) - {"managed_resources", "managed_termination"}:
                    raise _unavailable()
                updated = replace(expected, **changes)
                if updated != expected:
                    self._journal.put(updated)
                    expected = updated
                    if run_id in self._active:
                        self._active[run_id].record = expected
                return expected

        if expected.managed_termination is None or not expected.managed_termination.complete:
            await self._driver.retire_managed(expected, checkpoint)
        async with self._lifecycle:
            if (
                not unchanged()
                or expected.managed_termination is None
                or not expected.managed_termination.complete
            ):
                return False
            if not expected.process_stopped or expected.phase != "terminal":
                expected = replace(
                    expected,
                    process_stopped=True,
                    phase="terminal",
                    outcome=expected.outcome or "orphaned",
                    stop_kind=expected.stop_kind
                    if expected.process_stopped
                    else "managed_container",
                )
                self._journal.put(expected)
                if run_id in self._active:
                    self._active[run_id].record = expected
                    self._active[run_id].stopped = True
            digest = managed_retirement_proof_sha256(expected)
            stopped = []
            for peer in peers:
                if not peer.process_stopped:
                    peer = replace(
                        peer,
                        phase="terminal",
                        outcome=peer.outcome or "orphaned",
                        process_stopped=True,
                        stop_kind="managed_origin",
                        managed_origin_stop_sha256=digest,
                    )
                    self._journal.put(peer)
                    if peer.run_id in self._active:
                        self._active[peer.run_id].record = peer
                        self._active[peer.run_id].stopped = True
                stopped.append(peer)
        for row in (expected, *stopped):
            if self._closing:
                return False
            if row.run_id not in self._confirmed_recoveries:
                await self._confirm_recovery(row)
                self._confirmed_recoveries.add(row.run_id)
        if self._closing or not await self._driver.finish_managed_retirement(expected):
            return False
        self._completed_retirements.add(run_id)
        return True

    async def _recover_unknown_managed(self, record):
        if self._verify_released is None or self._closing:
            return False
        try:
            await self._verify_released(record)
            for peer in self._managed_peers(record):
                if peer.run_id in self._active or peer.phase != "terminal":
                    return False
                await self._verify_recovery(peer)
                await self._verify_released(peer)
        except RunnerControlError as error:
            if error.code == "interactive_controller_recovery_pending":
                return False
            raise

        async def checkpoint(**changes):
            async with self._lifecycle:
                current = self._journal.read(record.run_id)
                if (
                    self._closing
                    or record.run_id in self._active
                    or current.phase != "draining"
                    or current.outcome != "orphaned"
                    or current.process_stopped
                    or current.official_runner_id is not None
                    or current.managed_preparation != record.managed_preparation
                    or current.managed_creation != record.managed_creation
                    or current.connection_generation != self._generation
                    or current.product_revision != self._revision
                    or current.image_digest != self._image
                    or certificate_sha256(current.grant) != current.certificate_sha256
                    or any(
                        row.run_id in self._active or row.phase != "terminal"
                        for row in self._managed_peers(current)
                    )
                    or set(changes) - {"managed_resources", "managed_termination"}
                    or any(
                        getattr(current, key) != getattr(record, key)
                        for key in (
                            "run_id",
                            "fence_token",
                            "scope",
                            "runtime",
                            "grant",
                            "certificate_sha256",
                        )
                    )
                ):
                    raise _unavailable()
                updated = replace(current, **changes)
                if updated != current:
                    self._journal.put(updated)
                return updated

        try:
            await self._driver.recover_managed(record, checkpoint)
        except RunnerControlError as error:
            if error.code == "interactive_controller_unavailable":
                return False
            raise
        current = await checkpoint()
        async with self._lifecycle:
            if (
                self._closing
                or self._journal.read(record.run_id) != current
                or record.run_id in self._active
            ):
                return False
            if current.managed_termination is None or not current.managed_termination.complete:
                return False
            self._journal.put(
                replace(current, process_stopped=True, stop_kind="managed_container")
            )
            return True

    async def reconcile_physical_gc(self, *, limit: int) -> int:
        retirement_completed = 0
        origins = set()
        for row in self._journal.records():
            if row.run_id in self._completed_retirements:
                continue
            if row.managed_termination is not None and row.managed_resources is not None:
                origins.add(row.run_id)
                continue
            if row.process_stopped or not (
                row.outcome == "orphaned"
                or (row.phase != "terminal" and row.run_id not in self._active)
            ):
                continue
            if row.managed_origin_run_id is not None:
                origins.add(row.managed_origin_run_id)
            elif row.official_runner_id is not None and row.managed_resources is not None:
                origins.add(row.run_id)
        for run_id in sorted(origins, key=str)[:limit]:
            try:
                retirement_completed += await self.retire_managed_origin(
                    run_id,
                    cutoff=0,
                    now=int(datetime.now(timezone.utc).timestamp()),
                    force=True,
                )
            except RunnerControlError as error:
                if error.code != "interactive_controller_unavailable":
                    raise
        async with self._recovering:
            completed = retirement_completed
            for unstarted in self._journal.unstarted_records():
                if completed >= limit:
                    return completed
                if unstarted.run_id in self._confirmed_recoveries:
                    continue
                if (
                    unstarted.connection_generation != self._generation
                    or unstarted.product_revision != self._revision
                    or unstarted.image_digest != self._image
                    or unstarted.certificate_sha256
                    != sha256(self._recovery_certificate_path.read_bytes()).hexdigest()
                ):
                    raise _unavailable()
                await self._verify_recovery(unstarted)
                await self._confirm_recovery(unstarted)
                self._confirmed_recoveries.add(unstarted.run_id)
                completed += 1
            candidates = [
                row
                for row in self._journal.records()
                if row.phase != "terminal"
                or (
                    row.run_id in self._active
                    and row.process_stopped
                    and row.outcome == "orphaned"
                )
                or (
                    self._inspect_revocation is not None
                    and not row.process_stopped
                    and row.official_runner_id is not None
                )
                or any(row.grant.spool_directory.glob("*.pending.json"))
                or (
                    row.run_id not in self._confirmed_recoveries
                    and (
                        row.outcome == "orphaned"
                        or (
                            row.process_stopped
                            and (
                                row.official_runner_id is not None
                                or row.stop_kind == "never_started"
                            )
                        )
                    )
                )
            ]
            if candidates:
                offset = self._gc_offset % len(candidates)
                candidates = candidates[offset:] + candidates[:offset]
                self._gc_offset = offset + max(0, limit - completed)
            for candidate in candidates[: max(0, limit - completed)]:
                record = self._journal.read(candidate.run_id)
                if not await self._retire_orphaned(record):
                    continue
                await self._verify_recovery(record)
                if (
                    record.phase == "draining"
                    and record.outcome == "orphaned"
                    and not record.process_stopped
                    and record.official_runner_id is None
                    and record.managed_creation is not None
                ):
                    if not await self._recover_unknown_managed(record):
                        continue
                    record = self._journal.read(record.run_id)
                security_stop = (
                    record.phase == "terminal"
                    and not record.process_stopped
                    and self._inspect_revocation is not None
                    and await self._inspect_revocation(record)
                )
                if (
                    record.phase == "terminal"
                    and not record.process_stopped
                    and not security_stop
                    and not any(record.grant.spool_directory.glob("*.pending.json"))
                ):
                    continue
                confirmation_required = False
                async with self._lifecycle:
                    if (
                        record.run_id in self._active
                        or self._journal.read(record.run_id) != record
                    ):
                        continue
                    if (
                        record.connection_generation != self._generation
                        or record.product_revision != self._revision
                        or record.image_digest != self._image
                        or certificate_sha256(record.grant) != record.certificate_sha256
                    ):
                        raise _unavailable()
                    if (
                        security_stop
                        or record.phase != "terminal"
                        or (
                            (
                                record.outcome == "orphaned"
                                or (
                                    record.process_stopped
                                    and (
                                        record.official_runner_id is not None
                                        or record.stop_kind == "never_started"
                                    )
                                )
                            )
                            and record.run_id not in self._confirmed_recoveries
                        )
                    ):
                        never_started = (
                            record.phase == "prepared" and record.official_runner_id is None
                        )
                        peers = [
                            row
                            for row in self._journal.records()
                            if record.official_runner_id is not None
                            and row.run_id != record.run_id
                            and (
                                row.host_id,
                                row.official_runner_id,
                                row.host_owner,
                                row.host_account_generation,
                                row.scope.session_id,
                            )
                            == (
                                record.host_id,
                                record.official_runner_id,
                                record.host_owner,
                                record.host_account_generation,
                                record.scope.session_id,
                            )
                        ]
                        peers.extend(
                            row for row in self._managed_peers(record) if row not in peers
                        )
                        if any(
                            row.run_id in self._active or row.phase != "terminal" for row in peers
                        ):
                            continue
                        stopped = (
                            record.process_stopped
                            or never_started
                            or any(row.process_stopped for row in peers)
                            or await self._driver.stop(record)
                        )
                        if not stopped:
                            continue
                        if not record.process_stopped or never_started:
                            record = replace(
                                record,
                                process_stopped=True,
                                stop_kind="never_started" if never_started else record.stop_kind,
                            )
                            self._journal.put(record)
                        if security_stop and not any(
                            row.record.scope.session_id == record.scope.session_id
                            for row in self._active.values()
                        ):
                            await self._channels.forget(record.scope.session_id)
                        confirmation_required = True
                if confirmation_required:
                    await self._confirm_recovery(record)
                    async with self._lifecycle:
                        if (
                            record.run_id in self._active
                            or self._journal.read(record.run_id) != record
                        ):
                            continue
                        record = replace(
                            record,
                            phase="terminal",
                            process_stopped=True,
                            outcome=record.outcome if record.phase == "terminal" else "orphaned",
                        )
                        self._journal.put(record)
                        self._confirmed_recoveries.add(record.run_id)
                if record.stop_kind == "never_started" and not any(
                    record.grant.spool_directory.glob("*.pending.json")
                ):
                    completed += 1
                    continue
                meter = self._meter_factory(record.grant)
                try:
                    await asyncio.to_thread(meter.flush, 0)
                finally:
                    await asyncio.to_thread(meter.close, 0)
                completed += 1
            return completed

    async def shutdown(self) -> None:
        self._closing = True
        if self._retirements:
            await asyncio.wait(tuple(self._retirements.values()), timeout=15)
        await self._driver.shutdown_managed()
        for active in tuple(self._active.values()):
            with contextlib.suppress(Exception):
                await self.cancel(active.lease)
            await asyncio.to_thread(active.meter.close, 0)
            if active.handle is not None:
                await self._driver.release(active.handle)
