"""Deployable managed-Runner claim and fenced execution loop.

This is a control adapter, not a second execution engine.  A deployment-owned
executor factory must bind each opaque claimed Run to the existing managed
Omnigent Host/Runner runtime.  This loop owns only mTLS claim, liveness,
durable status transitions, and terminal capacity release.  Unknown-result
control mutations are never retried; the scheduler recovery loop remains the
authority after a transport or process failure.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import os
import re
import signal
import ssl
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from saas.production.preview_runner_tunnel import (
    ProductionPreviewRunnerTunnel,
    build_runner_preview_tunnel_client,
)
from saas.production.runner_control import (
    MutualTlsRunnerControlClient,
    RunnerControlClientLease,
    RunnerControlError,
    runner_identity_from_certificate,
)

_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_INTERNAL_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_TERMINAL_RESULTS = frozenset({"succeeded", "failed", "cancelled", "timed_out"})
_RUNNER_AGENT_DATABASE_FILE_ENV = "OMNIGENT_SAAS_RUNNER_AGENT_DATABASE_URL_FILE"
_FORBIDDEN_SECRET_ENVIRONMENTS = frozenset(
    {
        "OMNIGENT_SAAS_RUNNER_CONNECTION_TOKEN",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_KEY",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_CERTIFICATE",
        "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE",
    }
)
_LOGGER = logging.getLogger("omnigent-saas-production-runner")


class ProductionRunnerExecutor(Protocol):
    """Existing managed Runner runtime adapter selected by deployment."""

    def assert_production_ready(self) -> None: ...

    def assert_claimable(self) -> None: ...

    def bind_preview_runtime(self, supervisor: object) -> None: ...

    async def execute(
        self,
        lease: RunnerControlClientLease,
        *,
        cancellation: asyncio.Event,
    ) -> str: ...

    async def cancel(self, lease: RunnerControlClientLease) -> None: ...

    async def prepare_finalization(
        self,
        lease: RunnerControlClientLease,
        *,
        result: str,
    ) -> str: ...

    async def prepare_terminal_transition(self, lease: RunnerControlClientLease) -> None: ...

    async def finalize(self, lease: RunnerControlClientLease, *, result: str) -> None: ...

    async def reconcile_physical_gc(self, *, limit: int) -> int: ...


class RunnerControlClient(Protocol):
    async def heartbeat_runner(self) -> str: ...

    async def claim_run(self) -> RunnerControlClientLease | None: ...

    async def heartbeat_run(self, lease: RunnerControlClientLease) -> dict[str, object]: ...

    async def transition_run(
        self,
        lease: RunnerControlClientLease,
        *,
        target_status: str,
    ) -> dict[str, object]: ...

    async def release_run(self, lease: RunnerControlClientLease) -> bool: ...


class RunnerPreviewTunnelClient(Protocol):
    def assert_production_ready(self) -> None: ...

    async def run(self, stop: asyncio.Event) -> None: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionRunnerAgentConfig:
    product_revision: str
    image_digest: str
    runner_id: UUID
    connection_generation: int
    connection_token_path: Path = field(repr=False)
    ca_certificate_path: Path
    client_certificate_path: Path
    client_key_path: Path = field(repr=False)
    control_host: str
    control_port: int
    control_server_name: str
    executor_factory: str
    poll_interval_seconds: float
    heartbeat_interval_seconds: float
    request_timeout_seconds: float
    shutdown_timeout_seconds: float
    physical_gc_interval_seconds: float
    physical_gc_limit: int


@dataclass(frozen=True, slots=True)
class ProductionRunnerAgentStats:
    claims: int
    completed: int
    failed: int
    released: int
    physical_gc_cycles: int
    physical_gc_deleted: int
    physical_gc_failures: int


class ProductionRunnerAgent:
    """Consume leases sequentially with continuous fencing heartbeats."""

    def __init__(
        self,
        client: RunnerControlClient,
        executor: ProductionRunnerExecutor,
        *,
        poll_interval_seconds: float = 1.0,
        heartbeat_interval_seconds: float = 10.0,
        shutdown_timeout_seconds: float = 10.0,
        physical_gc_interval_seconds: float = 30.0,
        physical_gc_limit: int = 32,
        preview_tunnel: RunnerPreviewTunnelClient | None = None,
    ) -> None:
        if (
            not 0.05 <= poll_interval_seconds <= 60
            or not 1 <= heartbeat_interval_seconds <= 15
            or not 0.1 <= shutdown_timeout_seconds <= 60
            or not 1 <= physical_gc_interval_seconds <= 3600
            or not 1 <= physical_gc_limit <= 1000
        ):
            raise ValueError("Runner agent timing policy is invalid")
        self._client = client
        self._executor = executor
        self._poll_interval = poll_interval_seconds
        self._heartbeat_interval = heartbeat_interval_seconds
        self._shutdown_timeout = shutdown_timeout_seconds
        self._physical_gc_interval = physical_gc_interval_seconds
        self._physical_gc_limit = physical_gc_limit
        self._preview_tunnel = preview_tunnel

    async def _physical_gc_loop(self, stop: asyncio.Event) -> tuple[int, int, int]:
        cycles = deleted = failures = consecutive_failures = 0
        while not stop.is_set():
            try:
                count = await self._executor.reconcile_physical_gc(limit=self._physical_gc_limit)
            except Exception:  # noqa: BLE001 - storage/database details remain private.
                failures += 1
                consecutive_failures += 1
                delay = min(
                    300.0,
                    self._physical_gc_interval * (2 ** min(consecutive_failures - 1, 6)),
                )
                _LOGGER.error("production Runner physical GC cycle failed")
            else:
                cycles += 1
                deleted += count
                consecutive_failures = 0
                delay = self._physical_gc_interval
            try:
                await asyncio.wait_for(stop.wait(), timeout=delay)
            except TimeoutError:
                continue
        return cycles, deleted, failures

    async def _heartbeat_lease(
        self,
        lease: RunnerControlClientLease,
        stop: asyncio.Event,
        terminalizing: asyncio.Event,
    ) -> str:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._heartbeat_interval)
            except TimeoutError:
                state = await self._client.heartbeat_run(lease)
                status = state.get("status")
                if status == "cancelling":
                    return "cancelling"
                if terminalizing.is_set() and status in _TERMINAL_RESULTS | {"orphaned"}:
                    return "terminal"
                if status not in {
                    "leased",
                    "starting",
                    "running",
                    "waiting_input",
                    "waiting_approval",
                }:
                    raise RunnerControlError(
                        "runner_control_durable_status_invalid",
                        "Runner heartbeat returned an invalid durable status",
                    ) from None
        return "stopped"

    async def _cancel_execution(
        self,
        lease: RunnerControlClientLease,
        execution: asyncio.Task[str],
        cancellation: asyncio.Event,
    ) -> str:
        cancellation.set()
        try:
            await asyncio.wait_for(
                self._executor.cancel(lease),
                timeout=self._shutdown_timeout,
            )
            result = await asyncio.wait_for(execution, timeout=self._shutdown_timeout)
        except (TimeoutError, asyncio.CancelledError):
            execution.cancel()
            with suppress(asyncio.CancelledError):
                await execution
            return "orphaned"
        except Exception:  # noqa: BLE001 - executor failure detail is content-sensitive.
            execution.cancel()
            with suppress(asyncio.CancelledError):
                await execution
            return "orphaned"
        return "cancelled" if result in {"cancelled", "succeeded", "failed"} else "orphaned"

    async def _execute_lease(
        self,
        lease: RunnerControlClientLease,
        stop: asyncio.Event,
    ) -> str:
        initial = await self._client.heartbeat_run(lease)
        if initial.get("status") == "cancelling":
            await self._client.transition_run(lease, target_status="cancelled")
            await self._executor.finalize(lease, result="cancelled")
            await self._client.release_run(lease)
            return "cancelled"
        if initial.get("status") != "leased":
            raise RunnerControlError(
                "runner_control_durable_status_invalid",
                "Claimed Run is not durably leased",
            )
        await self._client.transition_run(lease, target_status="starting")
        await self._client.transition_run(lease, target_status="running")

        cancellation = asyncio.Event()
        heartbeat_stop = asyncio.Event()
        terminalizing = asyncio.Event()
        execution = asyncio.create_task(
            self._executor.execute(lease, cancellation=cancellation),
            name=f"runner-execute-{lease.run_id}",
        )
        heartbeat = asyncio.create_task(
            self._heartbeat_lease(lease, heartbeat_stop, terminalizing),
            name=f"runner-heartbeat-{lease.run_id}",
        )
        stopped = asyncio.create_task(stop.wait(), name=f"runner-stop-{lease.run_id}")
        durable_cancellation = False
        result = "orphaned"
        try:
            try:
                done, _pending = await asyncio.wait(
                    {execution, heartbeat, stopped},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if heartbeat in done:
                    try:
                        durable_status = await heartbeat
                    except Exception:
                        cancellation.set()
                        with suppress(Exception):
                            await asyncio.wait_for(
                                self._executor.cancel(lease), timeout=self._shutdown_timeout
                            )
                        execution.cancel()
                        with suppress(asyncio.CancelledError):
                            await execution
                        raise
                    if durable_status == "cancelling":
                        durable_cancellation = True
                        result = await self._cancel_execution(lease, execution, cancellation)
                    else:
                        raise RunnerControlError(
                            "runner_control_durable_status_invalid",
                            "Runner heartbeat stopped without cancellation",
                        )
                if stopped in done and execution not in done:
                    cancellation.set()
                    try:
                        result = await asyncio.wait_for(execution, timeout=self._shutdown_timeout)
                    except (TimeoutError, asyncio.CancelledError):
                        execution.cancel()
                        with suppress(asyncio.CancelledError):
                            await execution
                        result = "orphaned"
                    except Exception:  # noqa: BLE001 - executor errors are content-sensitive.
                        result = "failed"
                    if result not in _TERMINAL_RESULTS | {"orphaned"}:
                        result = "orphaned"
                elif heartbeat not in done:
                    try:
                        result = await execution
                    except asyncio.CancelledError:
                        raise
                    except Exception:  # noqa: BLE001 - executor errors are content-sensitive.
                        result = "failed"
                    if result not in _TERMINAL_RESULTS:
                        result = "failed"
            finally:
                stopped.cancel()
                with suppress(asyncio.CancelledError):
                    await stopped

            # Run and Worktree heartbeats deliberately remain live while helper
            # shutdown and checkpointing finish.  A failed checkpoint may only
            # downgrade the result, never preserve succeeded.
            try:
                prepared_result = await self._executor.prepare_finalization(
                    lease,
                    result=result,
                )
            except Exception:  # noqa: BLE001 - executor errors are content-sensitive.
                prepared_result = "orphaned"
            if prepared_result not in _TERMINAL_RESULTS | {"orphaned"}:
                prepared_result = "orphaned"
            result = prepared_result

            if heartbeat.done():
                durable_status = await heartbeat
                if durable_status == "cancelling":
                    durable_cancellation = True
                    if result != "orphaned":
                        result = "cancelled"
                else:
                    raise RunnerControlError(
                        "runner_control_durable_status_invalid",
                        "Runner heartbeat stopped before terminal transition",
                    )

            # Seal one final exact Worktree renewal while the Run lease is still
            # active.  Worktree release then follows the terminal transition
            # inside that fresh bounded fence window.
            await self._executor.prepare_terminal_transition(lease)

            # These are deliberate one-shot mutations.  If either response is
            # unknown, do not replay it; terminal-leak recovery releases capacity.
            if result == "cancelled" and not durable_cancellation:
                await self._client.transition_run(lease, target_status="cancelling")
            terminalizing.set()
            await self._client.transition_run(lease, target_status=result)
            heartbeat_stop.set()
            durable_status = await heartbeat
            if durable_status not in {"stopped", "cancelling", "terminal"}:
                raise RunnerControlError(
                    "runner_control_durable_status_invalid",
                    "Runner heartbeat stopped with an invalid terminal status",
                )
            await self._executor.finalize(lease, result=result)
            await self._client.release_run(lease)
            return result
        finally:
            heartbeat_stop.set()
            if not heartbeat.done():
                heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat

    async def _run_claim_loop(self, stop: asyncio.Event) -> ProductionRunnerAgentStats:
        self._executor.assert_production_ready()
        await self._client.heartbeat_runner()
        claims = completed = failed = released = 0
        gc_stop = asyncio.Event()
        gc_task = asyncio.create_task(self._physical_gc_loop(gc_stop), name="runner-physical-gc")
        try:
            while not stop.is_set():
                # A timeout leaves an uninterruptible daemon/DB call with an
                # unknown commit result.  The current lease may be recovered,
                # but this process incarnation must never claim another Run.
                self._executor.assert_claimable()
                await self._client.heartbeat_runner()
                lease = await self._client.claim_run()
                if lease is None:
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=self._poll_interval)
                    except TimeoutError:
                        continue
                    break
                claims += 1
                result = await self._execute_lease(lease, stop)
                released += 1
                if result == "succeeded":
                    completed += 1
                else:
                    failed += 1
        finally:
            gc_stop.set()
            gc_stats = await gc_task
        return ProductionRunnerAgentStats(
            claims,
            completed,
            failed,
            released,
            physical_gc_cycles=gc_stats[0],
            physical_gc_deleted=gc_stats[1],
            physical_gc_failures=gc_stats[2],
        )

    async def run(self, stop: asyncio.Event) -> ProductionRunnerAgentStats:
        preview = self._preview_tunnel
        if preview is None:
            return await self._run_claim_loop(stop)
        preview.assert_production_ready()
        claims = asyncio.create_task(self._run_claim_loop(stop), name="runner-claims")
        tunnel = asyncio.create_task(preview.run(stop), name="runner-preview-tunnel")
        unexpected_tunnel_exit: BaseException | None = None
        try:
            done, _pending = await asyncio.wait(
                {claims, tunnel}, return_when=asyncio.FIRST_COMPLETED
            )
            if tunnel in done and not stop.is_set():
                try:
                    await tunnel
                except asyncio.CancelledError as error:
                    unexpected_tunnel_exit = RunnerControlError(
                        "runner_preview_tunnel_cancelled",
                        "Preview tunnel was cancelled unexpectedly",
                    )
                    unexpected_tunnel_exit.__cause__ = error
                except Exception as error:  # noqa: BLE001 - propagate tunnel failure
                    unexpected_tunnel_exit = error
                else:
                    unexpected_tunnel_exit = RunnerControlError(
                        "runner_preview_tunnel_stopped",
                        "Preview tunnel stopped unexpectedly",
                    )
                stop.set()
            if claims in done:
                stop.set()
            try:
                stats = await asyncio.wait_for(
                    asyncio.shield(claims), timeout=self._shutdown_timeout
                )
            except TimeoutError:
                claims.cancel()
                with suppress(asyncio.CancelledError):
                    await claims
                raise RunnerControlError(
                    "runner_preview_tunnel_shutdown_timeout",
                    "Runner did not stop after Preview tunnel failure",
                ) from unexpected_tunnel_exit
            if tunnel not in done:
                await asyncio.wait_for(asyncio.shield(tunnel), timeout=self._shutdown_timeout)
            if unexpected_tunnel_exit is not None:
                raise unexpected_tunnel_exit
            return stats
        finally:
            await preview.aclose()
            for task in (claims, tunnel):
                if not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid")
    return value


def _reject_ambient_database_authority(source: Mapping[str, str]) -> None:
    for name, value in source.items():
        if not value.strip():
            continue
        database_authority = name in {"DATABASE_URL", "OMNIGENT_SAAS_DB_URL"} or name.endswith(
            ("_DATABASE_URL", "_DATABASE_URL_FILE")
        )
        if database_authority and name != _RUNNER_AGENT_DATABASE_FILE_ENV:
            raise RunnerControlError(
                "runner_agent_config_invalid",
                "Runner process received forbidden database authority",
            )


def _integer(
    source: Mapping[str, str], name: str, *, default: int, minimum: int, maximum: int
) -> int:
    try:
        value = int(source.get(name, str(default)))
    except ValueError as error:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid") from error
    if not minimum <= value <= maximum:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid")
    return value


def _number(
    source: Mapping[str, str], name: str, *, default: float, minimum: float, maximum: float
) -> float:
    try:
        value = float(source.get(name, str(default)))
    except ValueError as error:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid") from error
    if not minimum <= value <= maximum:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid")
    return value


def _secure_file(source: Mapping[str, str], name: str, *, secret: bool) -> Path:
    path = Path(_required(source, name))
    if not path.is_absolute():
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid") from error
    forbidden = 0o077 if secret else 0o022
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & forbidden
        or not 1 <= metadata.st_size <= 1_048_576
    ):
        raise RunnerControlError("runner_agent_config_invalid", f"{name} is invalid")
    return path


def _factory(source: Mapping[str, str]) -> str:
    value = _required(source, "OMNIGENT_SAAS_RUNNER_EXECUTOR_FACTORY")
    if _FACTORY_REFERENCE.fullmatch(value) is None or any(
        part.startswith("_") for part in value.replace(":", ".").split(".")
    ):
        raise RunnerControlError("runner_agent_config_invalid", "executor factory is invalid")
    return value


def load_production_runner_agent_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionRunnerAgentConfig:
    source: Mapping[str, str] = os.environ if environ is None else environ
    _reject_ambient_database_authority(source)
    if any(source.get(name, "").strip() for name in _FORBIDDEN_SECRET_ENVIRONMENTS):
        raise RunnerControlError(
            "runner_agent_config_invalid", "Runner agent secrets must use owner-only files"
        )
    product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    source_sha = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if (
        _FULL_GIT_SHA.fullmatch(product_revision) is None
        or _FULL_GIT_SHA.fullmatch(source_sha) is None
        or product_revision != source_sha
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
    ):
        raise RunnerControlError("runner_agent_config_invalid", "release identity is invalid")
    try:
        runner_id = UUID(_required(source, "OMNIGENT_SAAS_RUNNER_ID"))
    except ValueError as error:
        raise RunnerControlError(
            "runner_agent_config_invalid", "Runner identity is invalid"
        ) from error
    if str(runner_id) != source["OMNIGENT_SAAS_RUNNER_ID"] or runner_id.int == 0:
        raise RunnerControlError("runner_agent_config_invalid", "Runner identity is invalid")
    host = _required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_HOST").lower()
    server_name = _required(source, "OMNIGENT_SAAS_RUNNER_CONTROL_SERVER_NAME").lower()
    if _INTERNAL_HOST.fullmatch(host) is None or _INTERNAL_HOST.fullmatch(server_name) is None:
        raise RunnerControlError("runner_agent_config_invalid", "Runner endpoint is invalid")
    certificate = _secure_file(
        source,
        "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_CERTIFICATE_FILE",
        secret=False,
    )
    try:
        certificate_runner_id = runner_identity_from_certificate(certificate.read_bytes())
    except OSError as error:
        raise RunnerControlError(
            "runner_agent_config_invalid", "Runner certificate is unavailable"
        ) from error
    if certificate_runner_id != runner_id:
        raise RunnerControlError(
            "runner_agent_config_invalid", "Runner certificate identity does not match"
        )
    return ProductionRunnerAgentConfig(
        product_revision=product_revision,
        image_digest=image_digest,
        runner_id=runner_id,
        connection_generation=_integer(
            source,
            "OMNIGENT_SAAS_RUNNER_CONNECTION_GENERATION",
            default=1,
            minimum=1,
            maximum=(1 << 63) - 1,
        ),
        connection_token_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONNECTION_TOKEN_FILE", secret=True
        ),
        ca_certificate_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_CA_CERTIFICATE_FILE", secret=False
        ),
        client_certificate_path=certificate,
        client_key_path=_secure_file(
            source, "OMNIGENT_SAAS_RUNNER_CONTROL_CLIENT_KEY_FILE", secret=True
        ),
        control_host=host,
        control_port=_integer(
            source,
            "OMNIGENT_SAAS_RUNNER_CONTROL_PORT",
            default=9444,
            minimum=1,
            maximum=65535,
        ),
        control_server_name=server_name,
        executor_factory=_factory(source),
        poll_interval_seconds=_number(
            source,
            "OMNIGENT_SAAS_RUNNER_POLL_SECONDS",
            default=1.0,
            minimum=0.05,
            maximum=60,
        ),
        heartbeat_interval_seconds=_number(
            source,
            "OMNIGENT_SAAS_RUNNER_HEARTBEAT_SECONDS",
            default=10.0,
            minimum=1,
            maximum=15,
        ),
        request_timeout_seconds=_number(
            source,
            "OMNIGENT_SAAS_RUNNER_REQUEST_TIMEOUT_SECONDS",
            default=5.0,
            minimum=0.1,
            maximum=60,
        ),
        shutdown_timeout_seconds=_number(
            source,
            "OMNIGENT_SAAS_RUNNER_SHUTDOWN_TIMEOUT_SECONDS",
            default=10.0,
            minimum=0.1,
            maximum=60,
        ),
        physical_gc_interval_seconds=_number(
            source,
            "OMNIGENT_SAAS_RUNNER_PHYSICAL_GC_INTERVAL_SECONDS",
            default=30.0,
            minimum=1.0,
            maximum=3600.0,
        ),
        physical_gc_limit=_integer(
            source,
            "OMNIGENT_SAAS_RUNNER_PHYSICAL_GC_LIMIT",
            default=32,
            minimum=1,
            maximum=1000,
        ),
    )


def _call_factory(factory: Callable[..., object], config: ProductionRunnerAgentConfig) -> object:
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError) as error:
        raise RunnerControlError("runner_agent_config_invalid", "executor is invalid") from error
    if "config" in signature.parameters or any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return factory(config=config)
    required = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if required:
        raise RunnerControlError("runner_agent_config_invalid", "executor is invalid")
    return factory()


def load_production_runner_executor(
    config: ProductionRunnerAgentConfig,
) -> ProductionRunnerExecutor:
    module_name, attribute = config.executor_factory.split(":", 1)
    try:
        candidate = getattr(importlib.import_module(module_name), attribute)
        executor = _call_factory(candidate, config) if callable(candidate) else candidate
    except RunnerControlError:
        raise
    except Exception as error:
        raise RunnerControlError(
            "runner_agent_config_invalid", "executor factory failed"
        ) from error
    if (
        not callable(getattr(executor, "assert_production_ready", None))
        or not callable(getattr(executor, "assert_claimable", None))
        or not callable(getattr(executor, "bind_preview_runtime", None))
        or not callable(getattr(executor, "execute", None))
        or not callable(getattr(executor, "cancel", None))
        or not callable(getattr(executor, "prepare_finalization", None))
        or not callable(getattr(executor, "prepare_terminal_transition", None))
        or not callable(getattr(executor, "finalize", None))
        or not callable(getattr(executor, "reconcile_physical_gc", None))
    ):
        raise RunnerControlError("runner_agent_config_invalid", "executor is incomplete")
    return cast(ProductionRunnerExecutor, executor)


def build_runner_client(config: ProductionRunnerAgentConfig) -> MutualTlsRunnerControlClient:
    try:
        token = config.connection_token_path.read_text(encoding="utf-8").rstrip("\r\n")
    except (OSError, UnicodeError) as error:
        raise RunnerControlError(
            "runner_agent_config_invalid", "Runner connection token is unavailable"
        ) from error
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(config.ca_certificate_path),
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(
        certfile=str(config.client_certificate_path),
        keyfile=str(config.client_key_path),
    )
    return MutualTlsRunnerControlClient(
        connect_host=config.control_host,
        port=config.control_port,
        server_name=config.control_server_name,
        tls_context=context,
        connection_generation=config.connection_generation,
        connection_token=token,
        timeout_seconds=config.request_timeout_seconds,
    )


def verify_installed_runner_agent_lineage(config: ProductionRunnerAgentConfig) -> None:
    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise RunnerControlError(
            "runner_agent_config_invalid", "installed build revision is unavailable"
        ) from error
    if installed_revision != config.product_revision:
        raise RunnerControlError(
            "runner_agent_config_invalid", "installed build revision does not match"
        )


async def _run(config: ProductionRunnerAgentConfig) -> ProductionRunnerAgentStats:
    executor = load_production_runner_executor(config)
    control_client = build_runner_client(config)
    preview_tunnel: ProductionPreviewRunnerTunnel = build_runner_preview_tunnel_client(
        runner_id=config.runner_id,
        connection_generation=config.connection_generation,
        registration_client=control_client,
    )
    executor.bind_preview_runtime(preview_tunnel.supervisor)
    agent = ProductionRunnerAgent(
        control_client,
        executor,
        poll_interval_seconds=config.poll_interval_seconds,
        heartbeat_interval_seconds=config.heartbeat_interval_seconds,
        shutdown_timeout_seconds=config.shutdown_timeout_seconds,
        physical_gc_interval_seconds=config.physical_gc_interval_seconds,
        physical_gc_limit=config.physical_gc_limit,
        preview_tunnel=preview_tunnel,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for value in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(value, stop.set)
    return await agent.run(stop)


def main(_argv: Sequence[str] | None = None) -> int:
    config = load_production_runner_agent_config()
    verify_installed_runner_agent_lineage(config)
    asyncio.run(_run(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ProductionRunnerAgent",
    "ProductionRunnerAgentConfig",
    "ProductionRunnerAgentStats",
    "ProductionRunnerExecutor",
    "build_runner_client",
    "load_production_runner_agent_config",
    "load_production_runner_executor",
    "main",
    "verify_installed_runner_agent_lineage",
]
