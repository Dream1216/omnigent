"""Private Controller recovery facts; not a second financial ledger or task queue."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

from saas.compatibility import RuntimeContext
from saas.production.interactive_model_channel import ModelChannelScope
from saas.runner_adapter.metering import ManagedMeteringError, ManagedMeteringGrant

_MAX = 32768
_PHASES = {"prepared", "preparing", "launching", "ready", "dispatching", "draining", "terminal"}


class InteractiveRecoveryError(RuntimeError):
    def __init__(self):
        super().__init__("interactive_controller_recovery_unavailable")


@dataclass(frozen=True, slots=True)
class InteractiveRecoveryRecord:
    run_id: UUID
    fence_token: int
    connection_generation: int
    product_revision: str
    image_digest: str
    scope: ModelChannelScope
    runtime: RuntimeContext = field(repr=False)
    grant: ManagedMeteringGrant = field(repr=False)
    certificate_sha256: str
    phase: str = "prepared"
    host_id: str | None = None
    official_runner_id: str | None = None
    host_owner: str | None = None
    host_account_generation: str | None = None
    channel_value: str | None = field(default=None, repr=False)
    process_stopped: bool = False
    outcome: str | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if (
            self.run_id != self.grant.run_id
            or self.scope.session_id != self.grant.session_id
            or self.phase not in _PHASES
            or type(self.fence_token) is not int
            or self.fence_token < 1
            or type(self.connection_generation) is not int
            or self.connection_generation < 1
            or self.runtime.tenant_id != self.scope.tenant_id
            or self.runtime.space_id != self.scope.space_id
            or self.runtime.project_id != self.scope.project_id
            or self.runtime.actor_id != self.scope.actor_id
            or self.runtime.runtime_partition_id != self.scope.partition_id
            or not isinstance(self.product_revision, str)
            or re.fullmatch(r"[0-9a-f]{40}", self.product_revision) is None
            or not isinstance(self.image_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_digest) is None
            or not isinstance(self.certificate_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.certificate_sha256) is None
            or type(self.process_stopped) is not bool
            or self.outcome not in {None, "succeeded", "failed", "cancelled", "orphaned"}
            or not isinstance(self.updated_at, datetime)
            or self.updated_at.utcoffset() is None
            or (
                self.channel_value is not None
                and (
                    not isinstance(self.channel_value, str)
                    or re.fullmatch(r"[A-Za-z0-9_-]{43}", self.channel_value) is None
                )
            )
            or any(
                value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 256)
                for value in (
                    self.host_id,
                    self.official_runner_id,
                    self.host_owner,
                    self.host_account_generation,
                )
            )
        ):
            raise InteractiveRecoveryError()


def certificate_sha256(grant: ManagedMeteringGrant) -> str:
    # Pin the exact certificate file; rotation cannot silently rebind an old Run's receipts.
    return sha256(grant.client_certificate_path.read_bytes()).hexdigest()


def _encode(record: InteractiveRecoveryRecord) -> bytes:
    raw = json.dumps(
        {"schema_version": 1, "record": asdict(record)},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    if len(raw) > _MAX:
        raise InteractiveRecoveryError()
    return raw


def _object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise InteractiveRecoveryError()
        value[key] = entry
    return value


def _uuid(value):
    identifier = UUID(value)
    if str(identifier) != value or not identifier.int:
        raise InteractiveRecoveryError()
    return identifier


def _decode(raw: bytes) -> InteractiveRecoveryRecord:
    try:
        document = json.loads(raw, object_pairs_hook=_object)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "record"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
        ):
            raise ValueError
        value = document["record"]
        scope = value["scope"]
        for name in (
            "tenant_id",
            "space_id",
            "project_id",
            "actor_id",
            "session_id",
            "partition_id",
        ):
            scope[name] = _uuid(scope[name])
        runtime = value["runtime"]
        for name in (
            "actor_id",
            "tenant_id",
            "space_id",
            "project_id",
            "runtime_partition_id",
            "placement_id",
        ):
            runtime[name] = _uuid(runtime[name])
        grant = value["grant"]
        for name in ("session_id", "run_id", "runner_id"):
            grant[name] = _uuid(grant[name])
        for name in (
            "ca_certificate_path",
            "client_certificate_path",
            "client_key_path",
            "spool_directory",
        ):
            grant[name] = Path(grant[name])
        grant["expires_at"] = datetime.fromisoformat(grant["expires_at"])
        if grant["model_budget_reservation_id"] is not None:
            raise ValueError
        value["updated_at"] = datetime.fromisoformat(value["updated_at"])
        value.update(
            run_id=_uuid(value["run_id"]),
            scope=ModelChannelScope(**scope),
            runtime=RuntimeContext(**runtime),
            grant=ManagedMeteringGrant(**grant),
        )
        return InteractiveRecoveryRecord(**value)
    except (KeyError, TypeError, ValueError, UnicodeError, AttributeError, ManagedMeteringError):
        raise InteractiveRecoveryError() from None


class InteractiveRecoveryJournal:
    """One locked, owner-only Controller volume, never mounted into a workload."""

    def __init__(self, root: Path):
        if not root.is_absolute() or root.is_symlink():
            raise InteractiveRecoveryError()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise InteractiveRecoveryError()
        self.root = root
        self._directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._lock = -1
        try:
            self._lock = os.open(
                ".controller.lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._directory,
            )
            locked = os.fstat(self._lock)
            if (
                not stat.S_ISREG(locked.st_mode)
                or locked.st_uid != os.geteuid()
                or stat.S_IMODE(locked.st_mode) != 0o600
                or locked.st_nlink != 1
            ):
                raise InteractiveRecoveryError()
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, InteractiveRecoveryError):
            self.close()
            raise InteractiveRecoveryError() from None

    def _check(self):
        current, opened = self.root.lstat(), os.fstat(self._directory)
        if (
            (current.st_ino, current.st_dev) != (opened.st_ino, opened.st_dev)
            or not stat.S_ISDIR(current.st_mode)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            raise InteractiveRecoveryError()

    def put(self, record: InteractiveRecoveryRecord) -> None:
        self._check()
        try:
            previous = self.read(record.run_id)
        except FileNotFoundError:
            previous = None
        if previous is not None and any(
            getattr(previous, name) != getattr(record, name)
            for name in (
                "run_id",
                "fence_token",
                "connection_generation",
                "product_revision",
                "image_digest",
                "scope",
                "runtime",
                "grant",
                "certificate_sha256",
            )
        ):
            raise InteractiveRecoveryError()
        raw = _encode(record)
        name, temporary = f"{record.run_id}.json", f".{uuid4()}.temporary"
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._directory,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=self._directory, dst_dir_fd=self._directory)
            os.fsync(self._directory)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self._directory)

    def read(self, run_id: UUID) -> InteractiveRecoveryRecord:
        self._check()
        descriptor = os.open(f"{run_id}.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._directory)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or not 1 <= before.st_size <= _MAX
            ):
                raise InteractiveRecoveryError()
            raw = os.read(descriptor, _MAX + 1)
            after = os.fstat(descriptor)
            if (
                before.st_size != len(raw)
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_size != after.st_size
            ):
                raise InteractiveRecoveryError()
            record = _decode(raw)
            if record.run_id != run_id:
                raise InteractiveRecoveryError()
            return record
        finally:
            os.close(descriptor)

    def records(self) -> list[InteractiveRecoveryRecord]:
        self._check()
        return [
            self.read(_uuid(name[:-5]))
            for name in sorted(os.listdir(self._directory))
            if not name.startswith(".") and name.endswith(".json")
        ]

    def close(self) -> None:
        if getattr(self, "_lock", -1) >= 0:
            os.close(self._lock)
            self._lock = -1
        if getattr(self, "_directory", -1) >= 0:
            os.close(self._directory)
            self._directory = -1
