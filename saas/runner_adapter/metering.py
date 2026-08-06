"""Persist-first Provider usage metering for managed official Runners."""

from __future__ import annotations

import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Protocol, TypedDict
from uuid import UUID, uuid4

from omnigent.llms._usage_observer import add_required_observer
from saas.billing_metering_transport import MutualTlsBillingMeteringClient

MANAGED_METERING_ENVELOPE_ENV_VAR = "OMNIGENT_MANAGED_METERING_ENVELOPE"
_ENVELOPE_VERSION = 1
_SPOOL_VERSION = 1
_MAX_ENVELOPE_BYTES = 16_384
_MAX_SPOOL_BYTES = 32_768
_ENTRY_MODULE = "saas.runner_adapter.managed_entry"
_SAFE_PROVIDER = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENVELOPE_FIELDS = frozenset(
    {
        "ca_certificate_path",
        "capability_token",
        "client_certificate_path",
        "client_key_path",
        "expected_host",
        "expires_at",
        "metering_base_url",
        "official_runner_id",
        "run_id",
        "runner_id",
        "session_id",
        "spool_directory",
        "version",
    }
)
_SPOOL_FIELDS = frozenset(
    {
        "attributes",
        "event_id",
        "meters",
        "occurred_at",
        "provider",
        "provider_request_id",
        "run_id",
        "runner_id",
        "version",
    }
)
_METER_FIELDS = frozenset({"idempotency_key", "meter", "quantity", "unit"})
_ALLOWED_METERS = {
    "llm.input_tokens": "input",
    "llm.output_tokens": "output",
}


class ManagedMeteringError(RuntimeError):
    """Stable error that never renders the capability or certificate material."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ManagedMeteringGrant:
    """One scheduler-issued Run lease plus Runner mTLS client configuration."""

    session_id: UUID
    run_id: UUID
    runner_id: UUID
    capability_token: str = field(repr=False)
    expires_at: datetime
    metering_base_url: str
    expected_host: str
    ca_certificate_path: Path
    client_certificate_path: Path
    client_key_path: Path = field(repr=False)
    spool_directory: Path

    def __post_init__(self) -> None:
        if (
            not self.capability_token
            or len(self.capability_token) > 512
            or self.capability_token != self.capability_token.strip()
            or any(ord(char) < 32 for char in self.capability_token)
        ):
            raise ManagedMeteringError(
                "managed_metering_grant_invalid", "managed metering capability is invalid"
            )
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ManagedMeteringError(
                "managed_metering_grant_invalid", "managed metering expiry is invalid"
            )
        for path in (
            self.ca_certificate_path,
            self.client_certificate_path,
            self.client_key_path,
            self.spool_directory,
        ):
            if not path.is_absolute():
                raise ManagedMeteringError(
                    "managed_metering_grant_invalid", "managed metering paths must be absolute"
                )


class ManagedRunnerLaunchAuthority(Protocol):
    """One-time scheduler-to-Host handoff for an official launch frame."""

    def claim_metering_grant(
        self, *, session_id: str, official_runner_id: str
    ) -> ManagedMeteringGrant: ...


class StagedManagedRunnerLaunchAuthority:
    """Thread-safe one-time handoff populated by the durable scheduler dispatcher."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[UUID, ManagedMeteringGrant] = {}

    def stage(self, grant: ManagedMeteringGrant) -> None:
        with self._lock:
            if grant.session_id in self._grants:
                raise ManagedMeteringError(
                    "managed_metering_grant_conflict",
                    "a metering grant is already staged for this session",
                )
            self._grants[grant.session_id] = grant

    def claim_metering_grant(
        self, *, session_id: str, official_runner_id: str
    ) -> ManagedMeteringGrant:
        try:
            parsed_session = UUID(session_id)
        except (ValueError, AttributeError) as exc:
            raise ManagedMeteringError(
                "managed_metering_session_invalid", "managed launch session is invalid"
            ) from exc
        with self._lock:
            grant = self._grants.pop(parsed_session, None)
        if grant is None:
            raise ManagedMeteringError(
                "managed_metering_grant_missing", "managed launch has no staged metering grant"
            )
        if grant.expires_at <= datetime.now(timezone.utc):
            raise ManagedMeteringError(
                "managed_metering_grant_expired", "managed launch metering grant has expired"
            )
        if not official_runner_id or len(official_runner_id) > 256:
            raise ManagedMeteringError(
                "managed_metering_runner_invalid", "official Runner identity is invalid"
            )
        return grant


class _MeteringClient(Protocol):
    def record_usage(
        self,
        *,
        runner_id: UUID,
        capability_token: str,
        run_id: UUID,
        meter: str,
        quantity: Decimal | str | int,
        unit: str,
        provider: str,
        provider_request_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        attributes: dict[str, object] | None = None,
    ) -> object: ...

    def close(self) -> None: ...


class _SpoolMeter(TypedDict):
    idempotency_key: str
    meter: str
    quantity: int
    unit: str


class _ParsedSpool(TypedDict):
    attributes: dict[str, object]
    event_id: UUID
    meters: list[_SpoolMeter]
    occurred_at: datetime
    provider: str
    provider_request_id: str
    run_id: UUID
    runner_id: UUID
    version: int


def managed_runner_entry_module() -> str:
    return _ENTRY_MODULE


def write_metering_envelope(
    directory: Path,
    *,
    grant: ManagedMeteringGrant,
    official_runner_id: str,
) -> Path:
    """Publish a mode-0600, one-time launch envelope and fsync its directory."""

    _require_secure_directory(directory, create=True)
    document = {
        "ca_certificate_path": str(grant.ca_certificate_path),
        "capability_token": grant.capability_token,
        "client_certificate_path": str(grant.client_certificate_path),
        "client_key_path": str(grant.client_key_path),
        "expected_host": grant.expected_host,
        "expires_at": grant.expires_at.isoformat(),
        "metering_base_url": grant.metering_base_url,
        "official_runner_id": official_runner_id,
        "run_id": str(grant.run_id),
        "runner_id": str(grant.runner_id),
        "session_id": str(grant.session_id),
        "spool_directory": str(grant.spool_directory),
        "version": _ENVELOPE_VERSION,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > _MAX_ENVELOPE_BYTES:
        raise ManagedMeteringError(
            "managed_metering_envelope_invalid", "managed metering envelope is oversized"
        )
    path = directory / f"metering-{uuid4()}.json"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        path.unlink(missing_ok=True)
        _fsync_directory(directory)
        raise
    _fsync_directory(directory)
    return path


def consume_metering_envelope(
    path: Path,
    *,
    official_runner_id: str,
    now: datetime | None = None,
) -> ManagedMeteringGrant:
    """Read and unlink a one-time envelope before official Runner startup."""

    if not path.is_absolute():
        raise ManagedMeteringError(
            "managed_metering_envelope_invalid", "managed metering envelope path is invalid"
        )
    try:
        before = path.lstat()
    except (OSError, ValueError) as exc:
        raise ManagedMeteringError(
            "managed_metering_envelope_missing", "managed metering envelope is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.geteuid()
        or not 1 <= before.st_size <= _MAX_ENVELOPE_BYTES
    ):
        raise ManagedMeteringError(
            "managed_metering_envelope_invalid", "managed metering envelope ownership is invalid"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ManagedMeteringError(
                    "managed_metering_envelope_invalid",
                    "managed metering envelope identity changed",
                )
            encoded = _read_bounded(descriptor, _MAX_ENVELOPE_BYTES)
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_size != opened.st_size
                or len(encoded) != opened.st_size
            ):
                raise ManagedMeteringError(
                    "managed_metering_envelope_invalid",
                    "managed metering envelope changed while being consumed",
                )
        finally:
            os.close(descriptor)
        path.unlink()
        _fsync_directory(path.parent)
    except ManagedMeteringError:
        raise
    except (OSError, ValueError) as exc:
        raise ManagedMeteringError(
            "managed_metering_envelope_invalid", "managed metering envelope cannot be consumed"
        ) from exc
    try:
        document = _strict_object(encoded)
        if set(document) != _ENVELOPE_FIELDS or document["version"] != _ENVELOPE_VERSION:
            raise ValueError("invalid envelope schema")
        if document["official_runner_id"] != official_runner_id:
            raise ValueError("official runner mismatch")
        expires_at = _aware_datetime(document["expires_at"])
        grant = ManagedMeteringGrant(
            session_id=_canonical_uuid(document["session_id"]),
            run_id=_canonical_uuid(document["run_id"]),
            runner_id=_canonical_uuid(document["runner_id"]),
            capability_token=_text(document["capability_token"], 512),
            expires_at=expires_at,
            metering_base_url=_text(document["metering_base_url"], 2048),
            expected_host=_text(document["expected_host"], 253),
            ca_certificate_path=_absolute_path(document["ca_certificate_path"]),
            client_certificate_path=_absolute_path(document["client_certificate_path"]),
            client_key_path=_absolute_path(document["client_key_path"]),
            spool_directory=_absolute_path(document["spool_directory"]),
        )
    except (KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
        raise ManagedMeteringError(
            "managed_metering_envelope_invalid", "managed metering envelope body is invalid"
        ) from exc
    if expires_at <= (now or datetime.now(timezone.utc)):
        raise ManagedMeteringError(
            "managed_metering_grant_expired", "managed metering grant has expired"
        )
    return grant


def build_metering_client(grant: ManagedMeteringGrant) -> MutualTlsBillingMeteringClient:
    """Build the TLS-1.3-only Runner client from server-owned certificate paths."""

    import ssl

    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(grant.ca_certificate_path)
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_cert_chain(
        certfile=str(grant.client_certificate_path), keyfile=str(grant.client_key_path)
    )
    return MutualTlsBillingMeteringClient(
        base_url=grant.metering_base_url,
        runner_id=grant.runner_id,
        tls_context=context,
        expected_host=grant.expected_host,
    )


class ProviderUsageMeter:
    """Durably spool official Provider usage, then retry with stable identifiers."""

    def __init__(
        self,
        *,
        grant: ManagedMeteringGrant,
        client: _MeteringClient,
        retry_interval_seconds: float = 1.0,
    ) -> None:
        if retry_interval_seconds <= 0:
            raise ValueError("retry interval must be positive")
        _require_secure_directory(grant.spool_directory, create=True)
        self._grant = grant
        self._client = client
        self._retry_interval_seconds = retry_interval_seconds
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._drain_lock = threading.Lock()
        self._worker = threading.Thread(
            target=self._run,
            name=f"provider-usage-meter:{grant.run_id}",
            daemon=True,
        )
        self._worker.start()
        self._remove_observer: Callable[[], None] = add_required_observer(self._observe)
        self._wake.set()

    def _observe(
        self,
        *,
        model: str | None,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
    ) -> None:
        del total_tokens  # input/output are authoritative; never double-count total.
        meters: list[_SpoolMeter] = []
        event_id = uuid4()
        for suffix, meter, quantity in (
            ("input", "llm.input_tokens", input_tokens),
            ("output", "llm.output_tokens", output_tokens),
        ):
            if type(quantity) is int and quantity > 0:
                meters.append(
                    {
                        "idempotency_key": f"provider-usage:{event_id}:{suffix}",
                        "meter": meter,
                        "quantity": quantity,
                        "unit": "tokens",
                    }
                )
        if not meters:
            return
        provider = _provider_from_model(model)
        attributes: dict[str, object] = {"operation": "responses.create"}
        if (
            isinstance(model, str)
            and 0 < len(model) <= 256
            and all(ord(char) >= 32 for char in model)
        ):
            attributes["model"] = model
        document: dict[str, object] = {
            "attributes": attributes,
            "event_id": str(event_id),
            "meters": meters,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "provider_request_id": f"omnigent-observer-{event_id}",
            "run_id": str(self._grant.run_id),
            "runner_id": str(self._grant.runner_id),
            "version": _SPOOL_VERSION,
        }
        self._persist(document, event_id)
        self._wake.set()

    def _persist(self, document: dict[str, object], event_id: UUID) -> None:
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > _MAX_SPOOL_BYTES:
            raise ManagedMeteringError(
                "managed_metering_spool_invalid", "managed metering spool event is oversized"
            )
        directory = self._grant.spool_directory
        temporary = directory / f".{event_id}.{uuid4()}.tmp"
        pending = directory / f"{event_id}.pending.json"
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                _write_all(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, pending)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        _fsync_directory(directory)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self._retry_interval_seconds)
            self._wake.clear()
            self._drain_once()

    def _drain_once(self) -> bool:
        progressed = False
        with self._drain_lock:
            for path in sorted(self._grant.spool_directory.glob("*.pending.json")):
                try:
                    document = _read_spool(path, self._grant)
                    for meter in document["meters"]:
                        assert isinstance(meter, dict)
                        self._client.record_usage(
                            runner_id=self._grant.runner_id,
                            capability_token=self._grant.capability_token,
                            run_id=self._grant.run_id,
                            meter=meter["meter"],
                            quantity=meter["quantity"],
                            unit=meter["unit"],
                            provider=document["provider"],
                            provider_request_id=document["provider_request_id"],
                            idempotency_key=meter["idempotency_key"],
                            occurred_at=document["occurred_at"],
                            attributes=document["attributes"],
                        )
                except ManagedMeteringError:
                    rejected = path.with_suffix(".rejected.json")
                    os.replace(path, rejected)
                    _fsync_directory(path.parent)
                    progressed = True
                    continue
                except Exception:  # noqa: BLE001 -- preserve every unsent event for retry.
                    continue
                path.unlink(missing_ok=True)
                _fsync_directory(path.parent)
                progressed = True
        return progressed

    def flush(self, timeout_seconds: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            self._drain_once()
            if not any(self._grant.spool_directory.glob("*.pending.json")):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    def close(self, timeout_seconds: float = 5.0) -> bool:
        self._remove_observer()
        drained = self.flush(timeout_seconds)
        self._stop.set()
        self._wake.set()
        self._worker.join(timeout=max(0.1, timeout_seconds))
        self._client.close()
        return drained


def _read_spool(path: Path, grant: ManagedMeteringGrant) -> _ParsedSpool:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or not 1 <= before.st_size <= _MAX_SPOOL_BYTES
        ):
            raise ValueError("invalid spool file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("spool identity changed")
            encoded = _read_bounded(descriptor, _MAX_SPOOL_BYTES)
        finally:
            os.close(descriptor)
        if len(encoded) != opened.st_size:
            raise ValueError("spool size changed")
        document = _strict_object(encoded)
        if set(document) != _SPOOL_FIELDS or document["version"] != _SPOOL_VERSION:
            raise ValueError("invalid spool schema")
        if _canonical_uuid(document["run_id"]) != grant.run_id:
            raise ValueError("run mismatch")
        if _canonical_uuid(document["runner_id"]) != grant.runner_id:
            raise ValueError("runner mismatch")
        event_id = _canonical_uuid(document["event_id"])
        provider = _text(document["provider"], 64)
        if _SAFE_PROVIDER.fullmatch(provider) is None:
            raise ValueError("provider invalid")
        provider_request_id = _text(document["provider_request_id"], 256)
        occurred_at = _aware_datetime(document["occurred_at"])
        attributes = document["attributes"]
        meters = document["meters"]
        if not isinstance(attributes, dict) or set(attributes) not in (
            {"operation"},
            {"model", "operation"},
        ):
            raise ValueError("spool attributes invalid")
        if attributes.get("operation") != "responses.create":
            raise ValueError("spool operation invalid")
        if "model" in attributes:
            _text(attributes["model"], 256)
        if not isinstance(meters, list) or not 1 <= len(meters) <= 2:
            raise ValueError("spool values invalid")
        parsed_meters: list[_SpoolMeter] = []
        seen_meters: set[str] = set()
        for meter in meters:
            if not isinstance(meter, dict) or set(meter) != _METER_FIELDS:
                raise ValueError("meter invalid")
            quantity = meter["quantity"]
            if type(quantity) is not int or quantity <= 0:
                raise ValueError("quantity invalid")
            meter_name = _text(meter["meter"], 128)
            suffix = _ALLOWED_METERS.get(meter_name)
            if suffix is None or meter_name in seen_meters:
                raise ValueError("meter scope invalid")
            seen_meters.add(meter_name)
            if meter["unit"] != "tokens":
                raise ValueError("meter unit invalid")
            if meter["idempotency_key"] != f"provider-usage:{event_id}:{suffix}":
                raise ValueError("meter idempotency invalid")
            parsed_meters.append(
                {
                    "idempotency_key": _text(meter["idempotency_key"], 128),
                    "meter": meter_name,
                    "quantity": quantity,
                    "unit": _text(meter["unit"], 64),
                }
            )
        if provider_request_id != f"omnigent-observer-{event_id}":
            raise ValueError("provider request identity invalid")
        return {
            "attributes": attributes,
            "event_id": event_id,
            "meters": parsed_meters,
            "occurred_at": occurred_at,
            "provider": provider,
            "provider_request_id": provider_request_id,
            "run_id": grant.run_id,
            "runner_id": grant.runner_id,
            "version": _SPOOL_VERSION,
        }
    except (OSError, UnicodeDecodeError, ValueError, TypeError, KeyError) as exc:
        raise ManagedMeteringError(
            "managed_metering_spool_invalid", "managed metering spool event is invalid"
        ) from exc


def _provider_from_model(model: str | None) -> str:
    lowered = (model or "").strip().lower()
    if "/" in lowered:
        candidate = lowered.split("/", 1)[0]
        if _SAFE_PROVIDER.fullmatch(candidate):
            return candidate
    for token, provider in (
        ("claude", "anthropic"),
        ("gpt", "openai"),
        ("o1", "openai"),
        ("o3", "openai"),
        ("gemini", "google"),
        ("mistral", "mistral"),
    ):
        if token in lowered:
            return provider
    return "unknown"


def _require_secure_directory(path: Path, *, create: bool) -> None:
    if not path.is_absolute():
        raise ManagedMeteringError(
            "managed_metering_directory_invalid", "managed metering directory must be absolute"
        )
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise ManagedMeteringError(
            "managed_metering_directory_invalid", "managed metering directory is not private"
        )


def _strict_object(encoded: bytes) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(encoded.decode("utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("UUID invalid")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError("UUID non-canonical")
    return parsed


def _aware_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("datetime invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("datetime offset required")
    return parsed.astimezone(timezone.utc)


def _text(value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("text invalid")
    return value


def _absolute_path(value: object) -> Path:
    path = Path(_text(value, 4096))
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, encoded: bytes) -> None:
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("managed metering write made no progress")
        view = view[written:]


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 8192))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    encoded = b"".join(chunks)
    if len(encoded) > maximum:
        raise ValueError("managed metering document is oversized")
    return encoded


__all__ = [
    "MANAGED_METERING_ENVELOPE_ENV_VAR",
    "ManagedMeteringError",
    "ManagedMeteringGrant",
    "ManagedRunnerLaunchAuthority",
    "ProviderUsageMeter",
    "StagedManagedRunnerLaunchAuthority",
    "build_metering_client",
    "consume_metering_envelope",
    "managed_runner_entry_module",
    "write_metering_envelope",
]
