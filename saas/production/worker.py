"""Production Outbox projection and expired-lease recovery process.

The process owns two deliberately separate PostgreSQL authorities: a dispatcher
login claims and acknowledges Outbox rows, while an executor login projects
``run.queued`` events and recovers expired scheduling leases.  Owner or
migration credentials are never accepted by this long-running process.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import signal
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.outbox import (
    DispatchResult,
    OutboxClaimRoute,
    OutboxDispatcher,
    OutboxPublisher,
)
from saas.control_plane.run_dispatch_projection import RunQueuedDispatchProjection
from saas.control_plane.scheduling import SchedulingControlPlane
from saas.control_plane.worktrees import WorktreeControlPlane, WorktreeMutation
from saas.onboarding_composition import (
    validate_production_outbox_publisher,
    verify_onboarding_database_authority,
)
from saas.outbox_worker import verify_dispatcher_database_role
from saas.production.server import load_external_adapter
from saas.production.server_config import (
    ProductionMigrationReceipt,
    ProductionServerConfigError,
    load_production_database_url_file,
    load_production_migration_receipt,
)
from saas.production.service_bindings import (
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
)

_LOGGER = logging.getLogger("omnigent-saas-production-worker")
_FULL_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FACTORY_REFERENCE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*:[A-Za-z][A-Za-z0-9_]*$"
)
_WORKER_HEALTH_SCHEMA_VERSION = 1
_WORKER_HEALTH_FAILURE_CODES = frozenset(
    {
        "adapter_readiness_failed",
        "dispatch_failed",
        "lease_recovery_failed",
        "worktree_gc_failed",
        "worktree_recovery_failed",
    }
)
_WORKER_HEALTH_MAX_BYTES = 4_096
_FORBIDDEN_DATABASE_ENVIRONMENTS = frozenset(
    {
        "DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL",
        "OMNIGENT_SAAS_PRINCIPAL_OPERATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_DATABASE_OWNER_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_OFFICIAL_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_CONTROL_PLANE_MIGRATION_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_RUNTIME_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_AUTHENTICATOR_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_APP_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_GOVERNANCE_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PUBLIC_API_DATABASE_URL_FILE",
    }
)


class ProductionWorkerConfigError(ValueError):
    """Stable fail-closed worker configuration error."""


class ProductionWorkerHealthError(RuntimeError):
    """Stable fail-closed worker health-state error."""


@dataclass(frozen=True, slots=True)
class ProductionWorkerHealthPolicy:
    """Probe policy and owner-only state-file location."""

    state_path: Path
    readiness_max_age_seconds: float
    liveness_max_age_seconds: float
    max_consecutive_failures: int


@dataclass(frozen=True, slots=True)
class ProductionWorkerHealthState:
    """Content-blind progress facts shared with local Kubernetes probes."""

    startup_unix_ns: int
    last_loop_progress_unix_ns: int | None
    last_full_successful_cycle_unix_ns: int | None
    consecutive_failures: int
    failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.startup_unix_ns) is not int or self.startup_unix_ns <= 0:
            raise ProductionWorkerHealthError("worker health startup timestamp is invalid")
        for value in (
            self.last_loop_progress_unix_ns,
            self.last_full_successful_cycle_unix_ns,
        ):
            if value is not None and (type(value) is not int or value < self.startup_unix_ns):
                raise ProductionWorkerHealthError("worker health progress timestamp is invalid")
        if (
            self.last_full_successful_cycle_unix_ns is not None
            and self.last_loop_progress_unix_ns is not None
            and self.last_full_successful_cycle_unix_ns > self.last_loop_progress_unix_ns
        ):
            raise ProductionWorkerHealthError("worker health progress order is invalid")
        if type(self.consecutive_failures) is not int or self.consecutive_failures < 0:
            raise ProductionWorkerHealthError("worker health failure count is invalid")
        if (
            tuple(sorted(set(self.failure_codes))) != self.failure_codes
            or not set(self.failure_codes).issubset(_WORKER_HEALTH_FAILURE_CODES)
            or (self.consecutive_failures == 0) != (not self.failure_codes)
        ):
            raise ProductionWorkerHealthError("worker health failure classification is invalid")

    def document(self) -> dict[str, object]:
        return {
            "consecutive_failures": self.consecutive_failures,
            "failure_codes": list(self.failure_codes),
            "last_full_successful_cycle_unix_ns": self.last_full_successful_cycle_unix_ns,
            "last_loop_progress_unix_ns": self.last_loop_progress_unix_ns,
            "schema_version": _WORKER_HEALTH_SCHEMA_VERSION,
            "startup_unix_ns": self.startup_unix_ns,
        }


def _render_worker_health_state(state: ProductionWorkerHealthState) -> bytes:
    return (
        json.dumps(state.document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _parse_worker_health_state(payload: bytes) -> ProductionWorkerHealthState:
    if not 1 <= len(payload) <= _WORKER_HEALTH_MAX_BYTES:
        raise ProductionWorkerHealthError("worker health state size is invalid")
    try:
        text = payload.decode("ascii")
        document = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProductionWorkerHealthError("worker health state is invalid") from error
    expected_keys = {
        "consecutive_failures",
        "failure_codes",
        "last_full_successful_cycle_unix_ns",
        "last_loop_progress_unix_ns",
        "schema_version",
        "startup_unix_ns",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ProductionWorkerHealthError("worker health state shape is invalid")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != _WORKER_HEALTH_SCHEMA_VERSION
    ):
        raise ProductionWorkerHealthError("worker health state schema is invalid")
    codes = document["failure_codes"]
    if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
        raise ProductionWorkerHealthError("worker health failure classification is invalid")
    state = ProductionWorkerHealthState(
        startup_unix_ns=document["startup_unix_ns"],
        last_loop_progress_unix_ns=document["last_loop_progress_unix_ns"],
        last_full_successful_cycle_unix_ns=document["last_full_successful_cycle_unix_ns"],
        consecutive_failures=document["consecutive_failures"],
        failure_codes=tuple(codes),
    )
    if payload != _render_worker_health_state(state):
        raise ProductionWorkerHealthError("worker health state is not canonical")
    return state


class ProductionWorkerHealthStateWriter:
    """Atomically publish one exact-mode health document without following links."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise ProductionWorkerHealthError("worker health state path is invalid")
        self._path = path

    def write(self, state: ProductionWorkerHealthState) -> None:
        payload = _render_worker_health_state(state)
        directory = _open_private_worker_health_directory(self._path.parent)
        temporary_name = f".{self._path.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
        descriptor: int | None = None
        try:
            directory_metadata = os.fstat(directory)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            ):
                raise ProductionWorkerHealthError("worker health directory is invalid")
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ProductionWorkerHealthError("worker health state write failed")
                view = view[written:]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise ProductionWorkerHealthError("worker health state ownership is invalid")
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary_name,
                self._path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        except OSError as error:
            raise ProductionWorkerHealthError("worker health state write failed") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory)


def load_production_worker_health_state(path: Path) -> ProductionWorkerHealthState:
    """Read an exact owner-only health document without following its final path."""

    if not path.is_absolute():
        raise ProductionWorkerHealthError("worker health state path is invalid")
    directory = _open_private_worker_health_directory(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    except OSError as error:
        os.close(directory)
        raise ProductionWorkerHealthError("worker health state is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 1 <= metadata.st_size <= _WORKER_HEALTH_MAX_BYTES
        ):
            raise ProductionWorkerHealthError("worker health state ownership is invalid")
        chunks: list[bytes] = []
        remaining = _WORKER_HEALTH_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise ProductionWorkerHealthError("worker health state changed while reading")
        return _parse_worker_health_state(payload)
    finally:
        os.close(descriptor)
        os.close(directory)


def _open_private_worker_health_directory(path: Path) -> int:
    """Open every absolute directory component without following links."""

    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ProductionWorkerHealthError("worker health directory is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for part in path.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ProductionWorkerHealthError("worker health directory is unavailable") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise ProductionWorkerHealthError("worker health directory is invalid")
    return descriptor


def assert_production_worker_health(
    state: ProductionWorkerHealthState,
    policy: ProductionWorkerHealthPolicy,
    *,
    mode: str,
    now_unix_ns: int | None = None,
) -> None:
    """Apply the content-blind startup/readiness/liveness contract."""

    if mode not in {"startup", "readiness", "liveness"}:
        raise ProductionWorkerHealthError("worker health probe mode is invalid")
    now = time.time_ns() if now_unix_ns is None else now_unix_ns
    if type(now) is not int or now <= 0:
        raise ProductionWorkerHealthError("worker health probe clock is invalid")
    progress = state.last_loop_progress_unix_ns
    if progress is None or progress > now:
        raise ProductionWorkerHealthError("worker loop has not made valid progress")
    if mode == "liveness":
        maximum_age = int(policy.liveness_max_age_seconds * 1_000_000_000)
        if now - progress > maximum_age:
            raise ProductionWorkerHealthError("worker loop progress is stale")
        return
    successful = state.last_full_successful_cycle_unix_ns
    if successful is None or successful > now:
        raise ProductionWorkerHealthError("worker has not completed a successful cycle")
    maximum_age = int(policy.readiness_max_age_seconds * 1_000_000_000)
    if now - successful > maximum_age:
        raise ProductionWorkerHealthError("worker successful cycle is stale")
    if state.consecutive_failures >= policy.max_consecutive_failures:
        raise ProductionWorkerHealthError("worker consecutive failure limit was reached")


class _Dispatcher(Protocol):
    def dispatch_once(self, *, batch_size: int = 100) -> DispatchResult: ...


class _RecoveryAuthority(Protocol):
    def recover_expired_dispatches(
        self,
        *,
        max_fence_token: int = 3,
        limit: int = 100,
    ) -> tuple[UUID, ...]: ...


class _WorktreeRecoveryAuthority(Protocol):
    def expire_stale_leases(
        self,
        *,
        limit: int = 100,
    ) -> tuple[WorktreeMutation, ...]: ...

    def mark_gc_eligible(
        self,
        *,
        limit: int = 100,
    ) -> tuple[WorktreeMutation, ...]: ...


class _StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


class ProductionWorkerExternalAdapter(Protocol):
    """Readiness boundary for deployment-owned Runner or Preview transport."""

    def assert_production_ready(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ProductionWorkerConfig:
    """Validated non-secret facts and two narrow worker service DSNs."""

    product_revision: str
    image_digest: str
    official_schema_revision: str
    control_plane_schema_revision: str
    adapter_contract_version: str
    dispatcher_database_url: str = field(repr=False)
    executor_database_url: str = field(repr=False)
    runner_adapter_factory: str
    preview_adapter_factory: str
    batch_size: int
    max_attempts: int
    idle_interval_seconds: float
    error_backoff_seconds: float
    max_error_backoff_seconds: float
    recovery_interval_seconds: float
    recovery_limit: int
    worktree_recovery_interval_seconds: float
    worktree_gc_interval_seconds: float
    worktree_recovery_limit: int
    max_fence_token: int
    health_policy: ProductionWorkerHealthPolicy
    service_role_bindings: ProductionServiceRoleBindings = field(repr=False)
    migration_receipt: ProductionMigrationReceipt

    @property
    def version_document(self) -> Mapping[str, str]:
        """Expose only immutable, non-secret release facts."""

        return MappingProxyType(
            {
                "product_revision": self.product_revision,
                "image_digest": self.image_digest,
                "official_schema_revision": self.official_schema_revision,
                "control_plane_schema_revision": self.control_plane_schema_revision,
                "adapter_contract_version": self.adapter_contract_version,
                "service_role_bindings_sha256": self.service_role_bindings.sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class ProductionWorkerAdapters:
    """External availability checks; actual transports remain deployment-owned."""

    runner: ProductionWorkerExternalAdapter
    preview: ProductionWorkerExternalAdapter

    def assert_ready(self) -> None:
        self.runner.assert_production_ready()
        self.preview.assert_production_ready()


@dataclass(frozen=True, slots=True)
class ProductionWorkerStats:
    """Content-blind counters emitted after graceful shutdown."""

    dispatch_cycles: int
    claimed: int
    published: int
    event_failures: int
    quarantined: int
    dispatch_failures: int
    recovery_cycles: int
    recovered: int
    recovery_failures: int
    worktree_recovery_cycles: int
    worktrees_recovered: int
    worktree_recovery_failures: int
    worktree_gc_cycles: int
    worktrees_gc_eligible: int
    worktree_gc_failures: int
    adapter_readiness_failures: int


class ProductionRunSchedulerPublisher:
    """Route queued Run facts to the scheduler projection and preserve all other routes."""

    def __init__(
        self,
        projection: RunQueuedDispatchProjection,
        fallback: OutboxPublisher,
    ) -> None:
        if fallback is self:
            raise ValueError("production Outbox fallback must be a distinct publisher")
        self._projection = projection
        self._fallback = fallback
        self.validate_outbox_configuration()

    def validate_outbox_configuration(self) -> None:
        """Validate the complete fallback chain before the first claim."""

        if not callable(getattr(self._projection, "publish", None)):
            raise TypeError("Run dispatch projection does not provide publish()")
        validate_production_outbox_publisher(self._fallback)

    def publish(
        self,
        *,
        event_id: UUID,
        event_type: str,
        aggregate_type: str,
        aggregate_key: str,
        payload: dict[str, object],
    ) -> None:
        """Project only authoritative queue events; delegate every other event."""

        if payload.get("event_type") == "run.queued":
            self._projection.publish(
                event_id=event_id,
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_key=aggregate_key,
                payload=payload,
            )
            return
        self._fallback.publish(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_key=aggregate_key,
            payload=payload,
        )


class ProductionSchedulerWorker:
    """Drain Outbox events and recover expired leases on an independent cadence."""

    def __init__(
        self,
        dispatcher: _Dispatcher,
        recovery: _RecoveryAuthority,
        adapters: ProductionWorkerAdapters,
        *,
        batch_size: int = 100,
        idle_interval_seconds: float = 0.5,
        error_backoff_seconds: float = 1.0,
        max_error_backoff_seconds: float = 30.0,
        recovery_interval_seconds: float = 5.0,
        recovery_limit: int = 100,
        max_fence_token: int = 3,
        worktree_recovery: _WorktreeRecoveryAuthority | None = None,
        worktree_recovery_interval_seconds: float = 5.0,
        worktree_gc_interval_seconds: float = 30.0,
        worktree_recovery_limit: int = 100,
        clock: Callable[[], float] = time.monotonic,
        wall_clock_ns: Callable[[], int] = time.time_ns,
        health_writer: ProductionWorkerHealthStateWriter | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if not 1 <= batch_size <= 1000:
            raise ValueError("production worker batch size must be between 1 and 1000")
        if (
            min(
                idle_interval_seconds,
                error_backoff_seconds,
                max_error_backoff_seconds,
                recovery_interval_seconds,
                worktree_recovery_interval_seconds,
                worktree_gc_interval_seconds,
            )
            <= 0
        ):
            raise ValueError("production worker intervals must be positive")
        if max_error_backoff_seconds < error_backoff_seconds:
            raise ValueError("maximum error backoff must not be smaller than initial backoff")
        if (
            not 1 <= recovery_limit <= 1000
            or not 1 <= worktree_recovery_limit <= 1000
            or not 1 <= max_fence_token <= 100
        ):
            raise ValueError("production recovery policy is outside its bounded range")
        self._dispatcher = dispatcher
        self._recovery = recovery
        self._adapters = adapters
        self._batch_size = batch_size
        self._idle_interval = idle_interval_seconds
        self._error_backoff = error_backoff_seconds
        self._max_error_backoff = max_error_backoff_seconds
        self._recovery_interval = recovery_interval_seconds
        self._recovery_limit = recovery_limit
        self._max_fence_token = max_fence_token
        self._worktree_recovery = worktree_recovery
        self._worktree_recovery_interval = worktree_recovery_interval_seconds
        self._worktree_gc_interval = worktree_gc_interval_seconds
        self._worktree_recovery_limit = worktree_recovery_limit
        self._clock = clock
        self._wall_clock_ns = wall_clock_ns
        self._health_writer = health_writer
        self._logger = logger or _LOGGER

    def run(self, stop: _StopSignal) -> ProductionWorkerStats:
        """Run until signalled; provider and database errors remain content-blind."""

        dispatch_cycles = claimed = published = event_failures = quarantined = 0
        dispatch_failures = recovery_cycles = recovered = recovery_failures = 0
        worktree_recovery_cycles = worktrees_recovered = worktree_recovery_failures = 0
        worktree_gc_cycles = worktrees_gc_eligible = worktree_gc_failures = 0
        adapter_readiness_failures = 0
        consecutive_dispatch_errors = 0
        consecutive_recovery_errors = 0
        consecutive_worktree_recovery_errors = 0
        consecutive_worktree_gc_errors = 0
        active_failure_codes: set[str] = set()
        consecutive_full_cycle_failures = 0
        startup_unix_ns = self._wall_clock_ns()
        last_full_successful_cycle_unix_ns: int | None = None
        if self._health_writer is not None:
            self._health_writer.write(
                ProductionWorkerHealthState(
                    startup_unix_ns=startup_unix_ns,
                    last_loop_progress_unix_ns=None,
                    last_full_successful_cycle_unix_ns=None,
                    consecutive_failures=0,
                    failure_codes=(),
                )
            )
        next_recovery = self._clock()
        next_worktree_recovery = self._clock()
        next_worktree_gc = self._clock()
        while not stop.is_set():
            try:
                result = self._dispatcher.dispatch_once(batch_size=self._batch_size)
            except Exception:  # noqa: BLE001 - long-running process retries infrastructure faults.
                dispatch_failures += 1
                consecutive_dispatch_errors += 1
                active_failure_codes.add("dispatch_failed")
                delay = min(
                    self._max_error_backoff,
                    self._error_backoff * (2 ** min(consecutive_dispatch_errors - 1, 10)),
                )
                self._logger.error("production Outbox cycle failed; retrying")
            else:
                dispatch_cycles += 1
                claimed += result.claimed
                published += result.published
                event_failures += result.failed
                quarantined += result.quarantined
                consecutive_dispatch_errors = 0
                active_failure_codes.discard("dispatch_failed")
                delay = 0.0 if result.claimed == self._batch_size else self._idle_interval

            now = self._clock()
            if now >= next_recovery:
                try:
                    self._adapters.assert_ready()
                except Exception:  # noqa: BLE001 - external failure text can contain topology.
                    adapter_readiness_failures += 1
                    active_failure_codes.add("adapter_readiness_failed")
                    self._logger.error("production external adapter readiness failed")
                else:
                    active_failure_codes.discard("adapter_readiness_failed")
                try:
                    recovered_ids = self._recovery.recover_expired_dispatches(
                        max_fence_token=self._max_fence_token,
                        limit=self._recovery_limit,
                    )
                except Exception:  # noqa: BLE001 - database errors remain content-blind.
                    recovery_failures += 1
                    consecutive_recovery_errors += 1
                    active_failure_codes.add("lease_recovery_failed")
                    self._logger.error("production lease recovery cycle failed")
                    next_recovery = now + min(
                        self._max_error_backoff,
                        self._error_backoff * (2 ** min(consecutive_recovery_errors - 1, 10)),
                    )
                else:
                    recovery_cycles += 1
                    recovered += len(recovered_ids)
                    consecutive_recovery_errors = 0
                    active_failure_codes.discard("lease_recovery_failed")
                    next_recovery = now + self._recovery_interval

            if self._worktree_recovery is not None and now >= next_worktree_recovery:
                try:
                    expired = self._worktree_recovery.expire_stale_leases(
                        limit=self._worktree_recovery_limit
                    )
                except Exception:  # noqa: BLE001 - database errors remain content-blind.
                    worktree_recovery_failures += 1
                    consecutive_worktree_recovery_errors += 1
                    active_failure_codes.add("worktree_recovery_failed")
                    self._logger.error("production Worktree recovery cycle failed")
                    next_worktree_recovery = now + min(
                        self._max_error_backoff,
                        self._error_backoff
                        * (2 ** min(consecutive_worktree_recovery_errors - 1, 10)),
                    )
                else:
                    worktree_recovery_cycles += 1
                    worktrees_recovered += len(expired)
                    consecutive_worktree_recovery_errors = 0
                    active_failure_codes.discard("worktree_recovery_failed")
                    next_worktree_recovery = now + self._worktree_recovery_interval

            if self._worktree_recovery is not None and now >= next_worktree_gc:
                try:
                    eligible = self._worktree_recovery.mark_gc_eligible(
                        limit=self._worktree_recovery_limit
                    )
                except Exception:  # noqa: BLE001 - database errors remain content-blind.
                    worktree_gc_failures += 1
                    consecutive_worktree_gc_errors += 1
                    active_failure_codes.add("worktree_gc_failed")
                    self._logger.error("production Worktree GC eligibility cycle failed")
                    next_worktree_gc = now + min(
                        self._max_error_backoff,
                        self._error_backoff * (2 ** min(consecutive_worktree_gc_errors - 1, 10)),
                    )
                else:
                    worktree_gc_cycles += 1
                    worktrees_gc_eligible += len(eligible)
                    consecutive_worktree_gc_errors = 0
                    active_failure_codes.discard("worktree_gc_failed")
                    next_worktree_gc = now + self._worktree_gc_interval

            loop_progress_unix_ns = self._wall_clock_ns()
            if active_failure_codes:
                consecutive_full_cycle_failures += 1
            else:
                consecutive_full_cycle_failures = 0
                last_full_successful_cycle_unix_ns = loop_progress_unix_ns
            if self._health_writer is not None:
                self._health_writer.write(
                    ProductionWorkerHealthState(
                        startup_unix_ns=startup_unix_ns,
                        last_loop_progress_unix_ns=loop_progress_unix_ns,
                        last_full_successful_cycle_unix_ns=(last_full_successful_cycle_unix_ns),
                        consecutive_failures=consecutive_full_cycle_failures,
                        failure_codes=tuple(sorted(active_failure_codes)),
                    )
                )

            if delay > 0 and stop.wait(delay):
                break
        return ProductionWorkerStats(
            dispatch_cycles=dispatch_cycles,
            claimed=claimed,
            published=published,
            event_failures=event_failures,
            quarantined=quarantined,
            dispatch_failures=dispatch_failures,
            recovery_cycles=recovery_cycles,
            recovered=recovered,
            recovery_failures=recovery_failures,
            worktree_recovery_cycles=worktree_recovery_cycles,
            worktrees_recovered=worktrees_recovered,
            worktree_recovery_failures=worktree_recovery_failures,
            worktree_gc_cycles=worktree_gc_cycles,
            worktrees_gc_eligible=worktrees_gc_eligible,
            worktree_gc_failures=worktree_gc_failures,
            adapter_readiness_failures=adapter_readiness_failures,
        )


@dataclass(slots=True)
class BuiltProductionWorker:
    """Composed worker plus the two engines it exclusively owns."""

    worker: ProductionSchedulerWorker
    engines: tuple[Engine, Engine] = field(repr=False)

    def close(self) -> None:
        for engine in self.engines:
            engine.dispose()


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise ProductionWorkerConfigError(f"{name} is required and must be well formed")
    return value


def _revision(source: Mapping[str, str], name: str) -> str:
    value = _required(source, name)
    if _REVISION.fullmatch(value) is None:
        raise ProductionWorkerConfigError(f"{name} is invalid")
    return value


def _factory(source: Mapping[str, str], name: str) -> str:
    value = _required(source, name)
    if _FACTORY_REFERENCE.fullmatch(value) is None:
        raise ProductionWorkerConfigError(f"{name} must use a public module:attribute reference")
    module_name, attribute = value.split(":", 1)
    if any(part.startswith("_") for part in module_name.split(".")) or attribute.startswith("_"):
        raise ProductionWorkerConfigError(f"{name} must not reference private code")
    return value


def _bounded_integer(
    source: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = source.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ProductionWorkerConfigError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ProductionWorkerConfigError(f"{name} is outside its bounded range")
    return value


def _bounded_float(
    source: Mapping[str, str],
    name: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    raw = source.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as error:
        raise ProductionWorkerConfigError(f"{name} must be a number") from error
    if not minimum <= value <= maximum:
        raise ProductionWorkerConfigError(f"{name} is outside its bounded range")
    return value


def load_production_worker_health_policy(
    environ: Mapping[str, str] | None = None,
) -> ProductionWorkerHealthPolicy:
    """Load only the non-secret local probe policy."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    raw_path = _required(source, "OMNIGENT_SAAS_WORKER_HEALTH_STATE_FILE")
    state_path = Path(raw_path)
    if (
        not state_path.is_absolute()
        or state_path.name in {"", ".", ".."}
        or ".." in state_path.parts
    ):
        raise ProductionWorkerConfigError(
            "OMNIGENT_SAAS_WORKER_HEALTH_STATE_FILE must be an absolute normalized path"
        )
    return ProductionWorkerHealthPolicy(
        state_path=state_path,
        readiness_max_age_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_WORKER_HEALTH_READINESS_MAX_AGE_SECONDS",
            default=60.0,
            minimum=1.0,
            maximum=3600.0,
        ),
        liveness_max_age_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_WORKER_HEALTH_LIVENESS_MAX_AGE_SECONDS",
            default=120.0,
            minimum=1.0,
            maximum=3600.0,
        ),
        max_consecutive_failures=_bounded_integer(
            source,
            "OMNIGENT_SAAS_WORKER_HEALTH_MAX_CONSECUTIVE_FAILURES",
            default=5,
            minimum=1,
            maximum=100,
        ),
    )


def load_production_worker_config(
    environ: Mapping[str, str] | None = None,
) -> ProductionWorkerConfig:
    """Load a worker configuration without opening a database or adapter."""

    source: Mapping[str, str] = os.environ if environ is None else environ
    if any(source.get(name, "").strip() for name in _FORBIDDEN_DATABASE_ENVIRONMENTS):
        raise ProductionWorkerConfigError(
            "production worker must not receive ambient, server, owner, or migration DSNs"
        )
    product_revision = _required(source, "OMNIGENT_SAAS_SOURCE_SHA")
    if _FULL_GIT_SHA.fullmatch(product_revision) is None:
        raise ProductionWorkerConfigError("OMNIGENT_SAAS_SOURCE_SHA must be a full Git SHA")
    public_product_revision = _required(source, "OMNIGENT_SAAS_PRODUCT_REVISION")
    if _FULL_GIT_SHA.fullmatch(public_product_revision) is None:
        raise ProductionWorkerConfigError("OMNIGENT_SAAS_PRODUCT_REVISION must be a full Git SHA")
    if public_product_revision != product_revision:
        raise ProductionWorkerConfigError(
            "OMNIGENT_SAAS_PRODUCT_REVISION and OMNIGENT_SAAS_SOURCE_SHA must match exactly"
        )
    image_digest = _required(source, "OMNIGENT_SAAS_IMAGE_DIGEST")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise ProductionWorkerConfigError("OMNIGENT_SAAS_IMAGE_DIGEST must be a sha256 digest")
    official_head = _revision(source, "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION")
    saas_head = _revision(source, "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
    adapter_contract = _revision(source, "OMNIGENT_SAAS_ADAPTER_CONTRACT_VERSION")
    try:
        service_role_bindings = load_production_service_role_bindings(source)
        dispatcher_url, dispatcher_parsed, dispatcher_path = load_production_database_url_file(
            source, "dispatcher"
        )
        executor_url, executor_parsed, executor_path = load_production_database_url_file(
            source, "executor"
        )
        receipt = load_production_migration_receipt(
            source,
            product_revision=product_revision,
            official_head=official_head,
            saas_head=saas_head,
            service_role_bindings_sha256=service_role_bindings.sha256,
        )
    except (ProductionServerConfigError, ProductionServiceRoleBindingsError) as error:
        raise ProductionWorkerConfigError(str(error)) from error
    if (
        dispatcher_url == executor_url
        or dispatcher_path == executor_path
        or dispatcher_parsed.username == executor_parsed.username
    ):
        raise ProductionWorkerConfigError(
            "dispatcher and executor require distinct secret files, URLs, and logins"
        )
    dispatcher_endpoint = (
        dispatcher_parsed.host,
        dispatcher_parsed.port or 5432,
        dispatcher_parsed.database,
    )
    executor_endpoint = (
        executor_parsed.host,
        executor_parsed.port or 5432,
        executor_parsed.database,
    )
    if dispatcher_endpoint != executor_endpoint:
        raise ProductionWorkerConfigError(
            "dispatcher and executor must target the receipt-bound database"
        )
    if dispatcher_parsed.username != service_role_bindings.login_for("dispatcher"):
        raise ProductionWorkerConfigError(
            "dispatcher database URL login does not match service-role bindings"
        )
    if executor_parsed.username != service_role_bindings.login_for("executor"):
        raise ProductionWorkerConfigError(
            "executor database URL login does not match service-role bindings"
        )
    error_backoff = _bounded_float(
        source,
        "OMNIGENT_SAAS_WORKER_ERROR_BACKOFF_SECONDS",
        default=1.0,
        minimum=0.01,
        maximum=60.0,
    )
    max_error_backoff = _bounded_float(
        source,
        "OMNIGENT_SAAS_WORKER_MAX_ERROR_BACKOFF_SECONDS",
        default=30.0,
        minimum=0.01,
        maximum=300.0,
    )
    if max_error_backoff < error_backoff:
        raise ProductionWorkerConfigError(
            "worker maximum error backoff must not be smaller than initial backoff"
        )
    return ProductionWorkerConfig(
        product_revision=product_revision,
        image_digest=image_digest,
        official_schema_revision=official_head,
        control_plane_schema_revision=saas_head,
        adapter_contract_version=adapter_contract,
        dispatcher_database_url=dispatcher_url,
        executor_database_url=executor_url,
        runner_adapter_factory=_factory(source, "OMNIGENT_SAAS_WORKER_RUNNER_READINESS_FACTORY"),
        preview_adapter_factory=_factory(source, "OMNIGENT_SAAS_WORKER_PREVIEW_READINESS_FACTORY"),
        batch_size=_bounded_integer(
            source,
            "OMNIGENT_SAAS_WORKER_BATCH_SIZE",
            default=100,
            minimum=1,
            maximum=1000,
        ),
        max_attempts=_bounded_integer(
            source,
            "OMNIGENT_SAAS_WORKER_MAX_ATTEMPTS",
            default=8,
            minimum=1,
            maximum=32,
        ),
        idle_interval_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_WORKER_IDLE_SECONDS",
            default=0.5,
            minimum=0.01,
            maximum=60.0,
        ),
        error_backoff_seconds=error_backoff,
        max_error_backoff_seconds=max_error_backoff,
        recovery_interval_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_RECOVERY_INTERVAL_SECONDS",
            default=5.0,
            minimum=0.1,
            maximum=300.0,
        ),
        recovery_limit=_bounded_integer(
            source,
            "OMNIGENT_SAAS_RECOVERY_LIMIT",
            default=100,
            minimum=1,
            maximum=1000,
        ),
        worktree_recovery_interval_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_WORKTREE_RECOVERY_INTERVAL_SECONDS",
            default=5.0,
            minimum=0.1,
            maximum=300.0,
        ),
        worktree_gc_interval_seconds=_bounded_float(
            source,
            "OMNIGENT_SAAS_WORKTREE_GC_INTERVAL_SECONDS",
            default=30.0,
            minimum=1.0,
            maximum=3600.0,
        ),
        worktree_recovery_limit=_bounded_integer(
            source,
            "OMNIGENT_SAAS_WORKTREE_RECOVERY_LIMIT",
            default=100,
            minimum=1,
            maximum=1000,
        ),
        max_fence_token=_bounded_integer(
            source,
            "OMNIGENT_SAAS_MAX_FENCE_TOKEN",
            default=3,
            minimum=1,
            maximum=100,
        ),
        health_policy=load_production_worker_health_policy(source),
        service_role_bindings=service_role_bindings,
        migration_receipt=receipt,
    )


def verify_installed_worker_lineage(config: ProductionWorkerConfig) -> None:
    """Reject a stale image before opening either database connection."""

    try:
        from omnigent import _build_info

        installed_revision = _build_info.COMMIT_SHA
    except (AttributeError, ImportError) as error:
        raise RuntimeError("installed build revision is unavailable") from error
    if installed_revision != config.product_revision:
        raise RuntimeError("installed build revision does not match OMNIGENT_SAAS_SOURCE_SHA")


def load_production_worker_adapters(
    config: ProductionWorkerConfig,
) -> ProductionWorkerAdapters:
    """Load readiness contracts without claiming they implement external transports."""

    runner = load_external_adapter(config.runner_adapter_factory, cast(Any, config))
    preview = load_external_adapter(config.preview_adapter_factory, cast(Any, config))
    adapters = ProductionWorkerAdapters(runner=runner, preview=preview)
    adapters.assert_ready()
    return adapters


def build_production_worker(
    config: ProductionWorkerConfig,
    *,
    engine_factory: Callable[[str], Engine] = lambda url: sa.create_engine(
        url, pool_pre_ping=True
    ),
    adapter_loader: Callable[[ProductionWorkerConfig], ProductionWorkerAdapters] = (
        load_production_worker_adapters
    ),
) -> BuiltProductionWorker:
    """Compose the worker after live authority and adapter verification."""

    dispatcher_engine = engine_factory(config.dispatcher_database_url)
    executor_engine: Engine | None = None
    try:
        executor_engine = engine_factory(config.executor_database_url)
        if dispatcher_engine.dialect.name != "postgresql" or executor_engine.dialect.name != (
            "postgresql"
        ):
            raise RuntimeError("production worker authorities require PostgreSQL")
        verify_dispatcher_database_role(dispatcher_engine)
        verify_onboarding_database_authority(executor_engine, authority="execution")
        dispatcher_sessions = sessionmaker(
            dispatcher_engine,
            expire_on_commit=False,
            class_=Session,
        )
        executor_sessions = sessionmaker(
            executor_engine,
            expire_on_commit=False,
            class_=Session,
        )
        publisher = RunQueuedDispatchProjection(executor_sessions)
        adapters = adapter_loader(config)
        dispatcher = OutboxDispatcher(
            dispatcher_sessions,
            publisher,
            max_attempts=config.max_attempts,
            claim_routes=(
                OutboxClaimRoute(
                    aggregate_type="run",
                    event_type="run.event.persisted",
                    payload_event_type="run.queued",
                ),
            ),
        )
        recovery = SchedulingControlPlane(executor_sessions)
        worktree_recovery = WorktreeControlPlane(executor_sessions, scheduler=recovery)
        worker = ProductionSchedulerWorker(
            dispatcher,
            recovery,
            adapters,
            batch_size=config.batch_size,
            idle_interval_seconds=config.idle_interval_seconds,
            error_backoff_seconds=config.error_backoff_seconds,
            max_error_backoff_seconds=config.max_error_backoff_seconds,
            recovery_interval_seconds=config.recovery_interval_seconds,
            recovery_limit=config.recovery_limit,
            max_fence_token=config.max_fence_token,
            worktree_recovery=worktree_recovery,
            worktree_recovery_interval_seconds=config.worktree_recovery_interval_seconds,
            worktree_gc_interval_seconds=config.worktree_gc_interval_seconds,
            worktree_recovery_limit=config.worktree_recovery_limit,
            health_writer=ProductionWorkerHealthStateWriter(config.health_policy.state_path),
        )
        return BuiltProductionWorker(worker=worker, engines=(dispatcher_engine, executor_engine))
    except Exception:
        dispatcher_engine.dispose()
        if executor_engine is not None:
            executor_engine.dispose()
        raise


def main() -> int:
    """Verify exact lineage, compose both authorities, and run until SIGTERM."""

    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    config = load_production_worker_config()
    verify_installed_worker_lineage(config)
    built = build_production_worker(config)
    stop = threading.Event()

    def _stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        _LOGGER.info(
            "starting production scheduler worker revision=%s image_digest=%s",
            config.product_revision,
            config.image_digest,
        )
        stats = built.worker.run(stop)
        _LOGGER.info("production scheduler worker stopped: %s", stats)
        return 0
    finally:
        built.close()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BuiltProductionWorker",
    "ProductionRunSchedulerPublisher",
    "ProductionSchedulerWorker",
    "ProductionWorkerAdapters",
    "ProductionWorkerConfig",
    "ProductionWorkerConfigError",
    "ProductionWorkerExternalAdapter",
    "ProductionWorkerHealthError",
    "ProductionWorkerHealthPolicy",
    "ProductionWorkerHealthState",
    "ProductionWorkerHealthStateWriter",
    "ProductionWorkerStats",
    "assert_production_worker_health",
    "build_production_worker",
    "load_production_worker_adapters",
    "load_production_worker_config",
    "load_production_worker_health_policy",
    "load_production_worker_health_state",
    "main",
    "verify_installed_worker_lineage",
]
