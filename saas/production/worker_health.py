"""Local worker health metadata and probe policy without runtime dependencies."""

from __future__ import annotations

import json
import os
import secrets
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

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


def _required(source: Mapping[str, str], name: str) -> str:
    value = source.get(name)
    if value is None or not value.strip() or value != value.strip() or "\x00" in value:
        raise ProductionWorkerConfigError(f"{name} is required and must be well formed")
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
