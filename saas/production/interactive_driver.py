"""Drive existing official Host and session lifecycle under a delegated Runtime context."""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from threading import Event
from types import SimpleNamespace
from typing import Any, cast

import httpx

from omnigent.db.db_models import current_workspace_id
from omnigent.harness_aliases import canonicalize_harness
from omnigent.host.frames import HostLaunchRunnerFrame, decode_host_frame, encode_host_frame
from omnigent.runtime import session_stream
from omnigent.server.host_registry import host_owner_scope
from omnigent.server.managed_hosts import ManagedSandboxDeployment, parse_repo_workspace
from omnigent.server.routes._sessions import orchestration as official
from saas.compatibility import OmnigentStoreAdapter
from saas.production.interactive_controller import _unavailable
from saas.production.interactive_managed_generation import (
    ManagedGenerationAdmission,
    RetiredGenerationHostStore,
    inspect_retired_generation,
)
from saas.production.interactive_preparation import bind_managed_preparation
from saas.production.interactive_recovery import InteractiveRecoveryRecord
from saas.production.interactive_runtime import AuthorizedInteractiveInput

_PREPARATION_QUIESCE_TIMEOUT_S = 10


@dataclass(slots=True)
class InteractiveTurnObservation:
    future: asyncio.Future[str]
    armed: bool = False
    response_id: str | None = None

    def sdk(self, event: dict[str, Any]) -> None:
        if not self.armed or self.future.done():
            return
        response = event.get("response")
        identifier = response.get("id") if isinstance(response, dict) else None
        if not isinstance(identifier, str) or not identifier:
            return
        if event.get("type") == "response.in_progress" and self.response_id is None:
            self.response_id = identifier
        terminal = {
            "response.completed": "succeeded",
            "response.failed": "failed",
            "response.incomplete": "failed",
            "response.cancelled": "cancelled",
        }.get(str(event.get("type")))
        if terminal is not None and identifier == self.response_id:
            self.future.set_result(terminal)

    def native(self, data: dict[str, Any], *, harness: str | None = None) -> None:
        if not self.armed or self.future.done():
            return
        identifier = data.get("response_id")
        if not isinstance(identifier, str) or not identifier:
            return
        if data.get("status") == "running" and self.response_id is None:
            self.response_id = identifier
        outcome = data.get("turn_outcome")
        if data.get("interrupted") is True:
            outcome = "cancelled"
        elif data.get("status") == "failed":
            outcome = "failed"
        elif harness == "codex-native" and data.get("status") == "idle":
            outcome = "completed"
        if outcome is None and data.get("turn_completed") is True:
            outcome = "completed"
        terminal = {"completed": "succeeded", "failed": "failed", "cancelled": "cancelled"}.get(
            str(outcome)
        )
        if (
            identifier == self.response_id
            and (data.get("status") in {"idle", "failed"} or data.get("interrupted") is True)
            and terminal is not None
        ):
            self.future.set_result(terminal)


@dataclass(slots=True)
class _Handle:
    authorized: AuthorizedInteractiveInput
    conversation: Any
    client: httpx.AsyncClient
    native_ready: bool
    observation: InteractiveTurnObservation
    listener: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _Preparation:
    task: asyncio.Task
    stopping: Event


def _observe_preparation(task: asyncio.Task) -> None:
    if not task.cancelled():
        task.exception()


class _LaunchRegistry:
    def __init__(self, delegate, authorized, wire, tasks, *, stopping: Event | None = None):
        self._delegate, self._authorized, self._wire, self._tasks = (
            delegate,
            authorized,
            wire,
            tasks,
        )
        self._snapshot = copy.deepcopy(authorized.conversation.inference_snapshot)
        self._stopping = stopping

    def __getattr__(self, name):
        return getattr(self._delegate, name)

    async def admit_launch(
        self, connection, session_id, *, allow_unbound=False, transfer_from_host_id=None
    ):
        authorized = self._authorized
        if authorized.launch["host_type"] != "external":
            await self._delegate.admit_launch(
                connection,
                session_id,
                allow_unbound=allow_unbound,
                transfer_from_host_id=transfer_from_host_id,
            )
            return
        if (
            session_id != authorized.session_id
            or connection.host_id != authorized.launch["host_id"]
            or connection.workspace_id != authorized.runtime.physical_workspace_id
            or allow_unbound
            or transfer_from_host_id is not None
            or not isinstance(self._snapshot, dict)
            or not isinstance(authorized.publication, dict)
            or self._snapshot.get("managed_execution") != authorized.publication
            or self._delegate.launch_authorizer is None
        ):
            raise _unavailable()
        # Preserve locked ownership checks, adding only this frozen Server-authorized profile.
        await asyncio.to_thread(
            self._delegate.launch_authorizer,
            connection.host_id,
            session_id,
            connection.owner,
            connection.account_generation,
            False,
            None,
            expected_external_inference_snapshot=self._snapshot,
        )

    def send_text(self, connection, data):
        frame = decode_host_frame(data)
        if not isinstance(frame, HostLaunchRunnerFrame):
            return self._delegate.send_text(connection, data)
        if (
            (self._stopping is not None and self._stopping.is_set())
            or frame.session_id != self._authorized.session_id
            or "saas.model-channel.v1" not in connection.hello.capabilities
            or (
                self._authorized.launch["host_type"] == "external"
                and connection.host_id != self._authorized.launch["host_id"]
            )
        ):
            raise ConnectionError("interactive_host_unavailable")

        async def deliver():
            try:
                prepared = await self._wire(frame, connection)
                with host_owner_scope(connection.owner, connection.account_generation):
                    self._delegate.send_text(connection, encode_host_frame(prepared))
            except Exception:  # noqa: BLE001 - the launch result is deliberately content-blind.
                pending = connection.pending_launches.get(frame.request_id)
                if pending is not None and not pending.done():
                    pending.set_result(
                        {
                            "status": "failed",
                            "runner_id": None,
                            "error_code": "interactive_host_unavailable",
                            "error": "Managed launch unavailable",
                        }
                    )

        task = asyncio.create_task(deliver(), name="interactive-host-launch")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return None


class OfficialInteractiveDriver:
    def __init__(self, *, app: Any, dependencies: Any, contract_version: str):
        self._app, self._official = app, dependencies
        self._adapter = OmnigentStoreAdapter(contract_version)
        self._handles: dict[tuple[int, str], _Handle] = {}
        self._launch_tasks: dict[tuple[int, str], set[asyncio.Task]] = {}
        self._preparations: dict[tuple[int, str], _Preparation] = {}
        self._managed_recoveries: dict[object, asyncio.Task] = {}
        self._recovery_closing = False

    def assert_production_ready(self) -> None:
        state = self._app.state
        if (
            getattr(state, "host_registry", None) is None
            or getattr(state, "runner_router", None) is None
            or getattr(state, "tunnel_registry", None) is None
        ):
            raise _unavailable()

    def _key(self, authorized):
        return authorized.runtime.physical_workspace_id, authorized.session_id

    async def revalidate_managed(self, authorized, origins, *, previous=None):
        from saas.production.interactive_preparation import _binding, _direct_launcher
        from saas.production.interactive_resources import read_managed_resources

        with self._adapter.bind(authorized.runtime):
            conversation = await asyncio.to_thread(
                self._official.conversation_store.get_conversation, authorized.session_id
            )
        if conversation is None:
            raise _unavailable()
        if conversation.host_id is None:
            if previous is not None:
                raise _unavailable()
            return None
        candidates = [
            row
            for row in origins
            if row.managed_preparation.host_id == conversation.host_id
            and row.managed_preparation.provider == authorized.launch["sandbox_provider"]
            and row.managed_termination is None
        ]
        if len(candidates) != 1:
            if previous is None:

                def inspect():
                    with self._adapter.bind(authorized.runtime):
                        return inspect_retired_generation(self, authorized, origins, conversation)

                return await asyncio.to_thread(inspect)
            raise _unavailable()
        origin = candidates[0]
        if previous is not None:
            with self._adapter.bind(authorized.runtime):
                peer = self._app.state.host_registry.get(previous.host_id)
            if (
                peer is None
                or conversation.runner_id != previous.official_runner_id
                or (peer.owner, peer.account_generation)
                != (previous.host_owner, previous.host_account_generation)
            ):
                raise _unavailable()
        deployment = self._app.state.sandbox_config

        def verify():
            preparation, resource = origin.managed_preparation, origin.managed_resources
            delegate = _direct_launcher(
                deployment.for_provider(preparation.provider), preparation.provider
            )
            try:
                if (
                    _binding(delegate, preparation.resource_name, preparation.host_id)
                    != preparation
                ):
                    raise _unavailable()

                def host_token(token):
                    host = self._official.host_store.resolve_launch_token(
                        preparation.host_id, token
                    )
                    return (
                        host is not None
                        and (
                            host.host_id,
                            host.user_id,
                            host.account_generation,
                            host.sandbox_provider,
                            host.sandbox_id,
                            host.deleted_at,
                        )
                        == (
                            preparation.host_id,
                            origin.host_owner,
                            origin.host_account_generation,
                            preparation.provider,
                            preparation.resource_name,
                            None,
                        )
                        and host.terminating_sandbox_id != preparation.resource_name
                    )

                with self._adapter.bind(origin.runtime):
                    if (
                        read_managed_resources(
                            delegate,
                            preparation,
                            host_token_sha256=resource.host_token_sha256,
                            creation=origin.managed_creation,
                            validate_host_token=host_token,
                        )
                        != resource
                    ):
                        raise _unavailable()
                if origin.managed_creation.pod_uid is not None:
                    from saas.production.interactive_pod_binding import read_running_pod

                    read_running_pod(delegate, preparation, origin.managed_creation, resource)
            finally:
                delegate._close_clients()

        await asyncio.to_thread(verify)
        return origin

    async def prepare(
        self,
        authorized,
        *,
        previous,
        on_launch,
        on_preparation=None,
        on_resources=None,
        on_creation=None,
        generation: ManagedGenerationAdmission | None = None,
    ):
        key = self._key(authorized)
        if key in self._handles or key in self._preparations:
            raise _unavailable()
        stopping = Event()
        task = asyncio.create_task(
            self._prepare(
                authorized,
                previous=previous,
                on_launch=on_launch,
                on_preparation=on_preparation,
                on_resources=on_resources,
                on_creation=on_creation,
                generation=generation,
                stopping=stopping,
            ),
            name="interactive-physical-preparation",
        )
        entry = _Preparation(task, stopping)
        self._preparations[key] = entry
        task.add_done_callback(_observe_preparation)
        try:
            handle = await asyncio.shield(task)
        except asyncio.CancelledError:
            # A cancelled await does not stop the provider's underlying worker thread.
            stopping.set()
            raise
        except Exception:
            if self._preparations.get(key) is entry:
                del self._preparations[key]
            raise
        if self._preparations.get(key) is entry:
            del self._preparations[key]
        return handle

    async def _prepare(
        self,
        authorized,
        *,
        previous,
        on_launch,
        on_preparation,
        on_resources,
        on_creation,
        stopping,
        generation,
    ):
        self.assert_production_ready()
        key = self._key(authorized)
        if key in self._handles:
            raise _unavailable()
        tasks = self._launch_tasks.setdefault(key, set())
        state = SimpleNamespace(**self._app.state._state)
        host_store = self._official.host_store
        if generation is not None:
            if previous is not None or authorized.launch["host_type"] != "managed":
                raise _unavailable()
            with self._adapter.bind(authorized.runtime):
                if host_store.get_host(generation.host.host_id) != generation.host:
                    raise _unavailable()
            host_store = RetiredGenerationHostStore(host_store, generation.host)
        state.host_registry = _LaunchRegistry(
            state.host_registry, authorized, on_launch, tasks, stopping=stopping
        )
        if authorized.launch["host_type"] == "managed":
            if (
                on_preparation is None
                or on_resources is None
                or on_creation is None
                or not isinstance(state.sandbox_config, ManagedSandboxDeployment)
            ):
                raise _unavailable()
            state.sandbox_config = bind_managed_preparation(
                state.sandbox_config,
                provider=authorized.launch["sandbox_provider"],
                host_store=host_store,
                owner=authorized.runtime.runtime_user_key,
                checkpoint=on_preparation,
                checkpoint_resources=on_resources,
                checkpoint_creation=on_creation,
                stopping=stopping,
                loop=asyncio.get_running_loop(),
            )
        store = self._official.conversation_store
        with self._adapter.bind(authorized.runtime):
            conversation = await asyncio.to_thread(store.get_conversation, authorized.session_id)
            if conversation is None:
                raise _unavailable()
            if previous is not None:
                connection = state.host_registry.get(previous.host_id)
                if (
                    connection is None
                    or conversation.runner_id != previous.official_runner_id
                    or connection.owner != previous.host_owner
                    or connection.account_generation != previous.host_account_generation
                ):
                    raise _unavailable()
            if generation is not None and conversation.host_id != generation.host.host_id:
                raise _unavailable()
            if authorized.launch["host_type"] == "managed" and (
                conversation.host_id is None or generation is not None
            ):
                tracker = state.managed_launches
                if tracker.get(authorized.session_id) is not None:
                    raise _unavailable()
                tracker.begin(authorized.session_id)
                await official._run_managed_launch(
                    session_id=authorized.session_id,
                    owner=authorized.runtime.runtime_user_key,
                    sandbox_config=state.sandbox_config,
                    repos=[parse_repo_workspace(repo) for repo in authorized.launch["workspaces"]],
                    tracker=tracker,
                    conversation_store=store,
                    host_store=host_store,
                    host_registry=state.host_registry,
                    tunnel_registry=state.tunnel_registry,
                    provider=authorized.launch["sandbox_provider"],
                    agent_store=self._official.agent_store,
                    agent_id=conversation.agent_id,
                    relaunch_host=generation.host if generation is not None else None,
                )
                conversation = await asyncio.to_thread(
                    store.get_conversation, authorized.session_id
                )
            client, conversation = await official.ensure_runner_connected(
                session_id=authorized.session_id,
                conv=conversation,
                app_state=state,
                conversation_store=store,
                runner_router=state.runner_router,
                raise_host_refusal=True,
            )
            if client is None:
                raise _unavailable()
            native_ready = await official._ensure_runner_session_initialized(
                authorized.session_id,
                conversation,
                client,
                store,
                suppress_recovery_turn=True,
                require_success=True,
            )
            await official._ensure_runner_relay_ready(
                authorized.session_id,
                conversation.runner_id,
                client,
                store,
                conversation=conversation,
            )
            observation = InteractiveTurnObservation(asyncio.get_running_loop().create_future())
            handle = _Handle(authorized, conversation, client, native_ready, observation)
            stream = session_stream.subscribe(
                authorized.session_id, ready_event={"type": "controller.ready"}
            )
            await anext(stream)

            async def listen():
                try:
                    async for event in stream:
                        observation.sdk(event)
                except Exception:  # noqa: BLE001 - lost observations cannot prove task completion.
                    if not observation.future.done():
                        observation.future.set_result("orphaned")
                finally:
                    await cast(AsyncGenerator[dict[str, Any], None], stream).aclose()
                    if not observation.future.done():
                        observation.future.set_result("orphaned")

            handle.listener = asyncio.create_task(listen(), name="interactive-turn-observer")
            self._handles[key] = handle
            return handle

    async def dispatch(self, authorized, handle):
        handle = cast(_Handle, handle)
        if self._handles.get(self._key(authorized)) is not handle:
            raise _unavailable()
        with self._adapter.bind(authorized.runtime):
            handle.observation.armed = True
            await official._dispatch_session_event_to_runner_impl(
                authorized.session_id,
                handle.conversation,
                authorized.event,
                self._official.conversation_store,
                handle.client,
                agent_name=None,
                file_store=self._official.file_store,
                artifact_store=self._official.artifact_store,
                created_by=authorized.runtime.runtime_user_key,
                runner_router=self._app.state.runner_router,
                host_registry=self._app.state.host_registry,
                host_store=self._official.host_store,
                native_terminal_ready=handle.native_ready,
                background_titles_enabled=False,
            )

    async def outcome(self, authorized, handle):
        if self._handles.get(self._key(authorized)) is not handle:
            raise _unavailable()
        return await cast(_Handle, handle).observation.future

    def observe_runtime_status(self, conversation, data):
        handle = self._handles.get((current_workspace_id(), conversation.id))
        if handle is not None and handle.conversation.runner_id == conversation.runner_id:
            handle.observation.native(
                data, harness=canonicalize_harness(handle.authorized.launch["harness"])
            )

    async def quiesce_preparation(self, authorized):
        key = self._key(authorized)
        entry = self._preparations.get(key)
        if entry is not None:
            entry.stopping.set()
        tasks = self._launch_tasks.get(key, set())
        for task in tuple(tasks):
            task.cancel()
        if tasks:
            await asyncio.gather(*tuple(tasks), return_exceptions=True)
        if entry is not None:
            done, _ = await asyncio.wait({entry.task}, timeout=_PREPARATION_QUIESCE_TIMEOUT_S)
            if not done:
                raise _unavailable()
            try:
                handle = entry.task.result()
            except Exception:  # noqa: BLE001 - a failed pipeline is not a stop acknowledgement.
                handle = None
            if handle is not None and self._handles.get(key) is handle:
                await self.release(handle)
            if self._preparations.get(key) is entry:
                del self._preparations[key]

    async def recover_managed(self, record, checkpoint):
        return await self._recover_resources(record, checkpoint, retiring=False)

    async def inspect_managed_retirement(self, record, *, cutoff, now, force=False):
        from saas.production.interactive_managed_retirement import read_retirement_host

        return await asyncio.to_thread(
            read_retirement_host, self, record, cutoff=cutoff, now=now, force=force
        )

    async def detach_managed_retirement(self, record, host):
        from saas.production.interactive_managed_retirement import detach_retirement_host

        return await asyncio.to_thread(detach_retirement_host, self, record, host)

    async def retire_managed(self, record, checkpoint):
        return await self._recover_resources(record, checkpoint, retiring=True)

    async def finish_managed_retirement(self, record):
        from saas.production.interactive_managed_retirement import finish_retirement_host

        return await asyncio.to_thread(finish_retirement_host, self, record)

    async def _recover_resources(self, record, checkpoint, *, retiring):
        from saas.production.interactive_managed_recovery import (
            recover_managed_resources,
            retire_managed_resources,
        )

        if self._recovery_closing:
            raise _unavailable()
        task = self._managed_recoveries.get(record.run_id)
        if task is None:

            async def recover():
                with self._adapter.bind(record.runtime):
                    return await (
                        retire_managed_resources if retiring else recover_managed_resources
                    )(self._app.state.sandbox_config, record, checkpoint)

            task = asyncio.create_task(
                recover(),
                name="interactive-managed-resource-recovery",
            )
            task.add_done_callback(_observe_preparation)
            self._managed_recoveries[record.run_id] = task
        try:
            return await asyncio.shield(task)
        finally:
            if task.done() and self._managed_recoveries.get(record.run_id) is task:
                del self._managed_recoveries[record.run_id]

    async def shutdown_managed(self):
        self._recovery_closing = True
        if self._managed_recoveries:
            await asyncio.wait(tuple(self._managed_recoveries.values()), timeout=15)

    async def stop(self, record: InteractiveRecoveryRecord) -> bool:
        if record.host_id is None or record.official_runner_id is None:
            return False
        with self._adapter.bind(record.runtime):
            registry = self._app.state.host_registry
            connection = registry.get(record.host_id)
            if (
                connection is None
                or connection.workspace_id != record.runtime.physical_workspace_id
                or connection.owner != record.host_owner
                or connection.account_generation != record.host_account_generation
            ):
                return False
            with host_owner_scope(record.host_owner, record.host_account_generation):
                return await official._stop_host_runner_intentionally(
                    record.scope.official_session_id,
                    record.host_id,
                    record.official_runner_id,
                    registry,
                    self._official.conversation_store,
                )

    async def release(self, handle):
        handle = cast(_Handle, handle)
        key = self._key(handle.authorized)
        preparing = self._preparations.get(key)
        if preparing is not None and not preparing.task.done():
            raise _unavailable()
        self._handles.pop(key, None)
        self._launch_tasks.pop(key, None)
        if handle.listener is not None:
            handle.listener.cancel()
            await asyncio.gather(handle.listener, return_exceptions=True)
