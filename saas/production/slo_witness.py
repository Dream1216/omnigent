"""Independent, version-locked Run Event ACK checkpoints, outside the source DB."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any, Protocol

_MAX_SEQUENCE = 2**63 - 1


class WitnessUnavailable(RuntimeError):
    """A committed operation must not return an unwitnessed successful ACK."""


class WitnessDeadlineExceeded(WitnessUnavailable):
    """Stop aggregate recovery I/O after the shared monotonic work budget."""


class WitnessConflict(WitnessUnavailable):
    """The same Run/sequence cannot represent two event contents."""


class WitnessBackfillRequired(WitnessUnavailable):
    """A bounded background recovery must establish the older event prefix."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class StoredObject:
    body: bytes
    etag: str
    version: str


class WitnessStore(Protocol):
    """Independent durable conditional writes; adapter qualification proves retention."""

    def read(self, key: str) -> StoredObject | None: ...

    def first(self, prefix: str) -> tuple[str, StoredObject] | None: ...

    def conditional_put(
        self, key: str, body: bytes, *, expected_etag: str | None
    ) -> StoredObject: ...


@dataclass(frozen=True)
class WitnessEvent:
    sequence: int
    content: dict[str, object]


class RunEventWitness:
    """Append bounded events and immutable checkpoints after source DB commit."""

    def __init__(
        self,
        store: WitnessStore,
        *,
        product_revision: str,
        key_version: str,
        hmac_key: bytes,
        max_segment: int = 128,
    ) -> None:
        if len(product_revision) != 40 or any(
            c not in "0123456789abcdef" for c in product_revision
        ):
            raise ValueError("witness product revision must be an exact SHA")
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", key_version) is None
            or len(hmac_key) < 32
            or not 1 <= max_segment <= 256
        ):
            raise ValueError("witness key or segment configuration is invalid")
        self.store = store
        self.product_revision = product_revision
        self.key_version = key_version
        self._key = hmac_key
        self.max_segment = max_segment
        self._deadline: ContextVar[float | None] = ContextVar("witness_deadline", default=None)
        self._epoch_checked = False
        self._epoch_lock = threading.RLock()

    @contextmanager
    def budget(self, deadline: float):
        """Cooperative aggregate budget; an in-flight SDK call retains its own timeout.

        This never abandons a write in a worker thread or silently retries an
        uncertain result. The supervisor still owns any absolute wall deadline.
        """
        previous = self._deadline.get()
        token = self._deadline.set(deadline if previous is None else min(previous, deadline))
        try:
            self._check_budget()
            yield
            self._check_budget()
        finally:
            self._deadline.reset(token)

    def _check_budget(self) -> None:
        deadline = self._deadline.get()
        if deadline is not None and time.monotonic() >= deadline:
            raise WitnessDeadlineExceeded("independent witness recovery I/O budget exhausted")

    def _store_call(self, name, *args, **kwargs):
        self._check_budget()
        result = getattr(self.store, name)(*args, **kwargs)
        self._check_budget()
        return result

    def _read(self, key):
        return self._store_call("read", key)

    def _first(self, prefix):
        return self._store_call("first", prefix)

    def _put(self, key, body, *, expected_etag):
        return self._store_call("conditional_put", key, body, expected_etag=expected_etag)

    def bind_epoch(self) -> None:
        """An accidentally changed HMAC key cannot silently create a second history."""
        with self._epoch_lock:
            if self._epoch_checked:
                return
            key = f"{self.product_revision}/{self.key_version}/epoch.json"
            body = self._seal(
                {
                    "schema_version": 1,
                    "product_revision": self.product_revision,
                    "key_version": self.key_version,
                    "key_fingerprint": self.identifier("saas-slo-witness-epoch"),
                }
            )
            existing = self._read(key)
            if existing is None:
                try:
                    existing = self._put(key, body, expected_etag=None)
                except WitnessConflict:
                    existing = self._read(key)
            if existing is None or not hmac.compare_digest(existing.body, body):
                raise WitnessConflict("witness epoch key binding changed")
            self._epoch_checked = True

    def identifier(self, value: str) -> str:
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()

    def prefix(self, tenant: str, run: str) -> str:
        return (
            f"{self.product_revision}/{self.key_version}/"
            f"{self.identifier(tenant)}/{self.identifier(run)}/"
        )

    def checkpoint(
        self, tenant: str, run: str
    ) -> tuple[dict[str, Any] | None, StoredObject | None]:
        self.bind_epoch()
        prefix = self.prefix(tenant, run) + "heads/"
        first = self._first(prefix)
        if first is None:
            return None, None
        key, result = first
        value = self._decode(result.body)
        if set(value) != {
            "schema_version",
            "product_revision",
            "key_version",
            "run_hmac",
            "sequence",
            "event_digest",
            "mac",
        }:
            raise WitnessConflict("witness checkpoint fields are invalid")
        expected = self._seal({k: v for k, v in value.items() if k != "mac"})
        if not hmac.compare_digest(result.body, expected):
            raise WitnessConflict("witness checkpoint authentication failed")
        if (
            value["schema_version"] != 1
            or value["product_revision"] != self.product_revision
            or value["key_version"] != self.key_version
            or value["run_hmac"] != self.identifier(tenant + "/" + run)
            or type(value["sequence"]) is not int
            or not 1 <= value["sequence"] <= _MAX_SEQUENCE
            or key != prefix + f"{_MAX_SEQUENCE - value['sequence']:020d}.json"
        ):
            raise WitnessConflict("witness checkpoint binding is invalid")
        return value, result

    def _acknowledged_floor(self, tenant: str, run: str) -> int:
        prefix = self.prefix(tenant, run) + "acknowledged-heads/"
        first = self._first(prefix)
        if first is None:
            return 0
        key, stored = first
        value = self._decode(stored.body)
        payload = {k: v for k, v in value.items() if k != "mac"}
        if (
            set(value)
            != {"schema_version", "product_revision", "key_version", "run_hmac", "sequence", "mac"}
            or not hmac.compare_digest(stored.body, self._seal(payload))
            or value["schema_version"] != 1
            or value["product_revision"] != self.product_revision
            or value["key_version"] != self.key_version
            or value["run_hmac"] != self.identifier(tenant + "/" + run)
            or type(value["sequence"]) is not int
            or not 1 <= value["sequence"] <= _MAX_SEQUENCE
            or key != prefix + f"{_MAX_SEQUENCE - value['sequence']:020d}.json"
        ):
            raise WitnessConflict("acknowledged sequence floor is invalid")
        return value["sequence"]

    def observed_floor(self, tenant: str, run: str) -> int:
        """Read before the source statement, without holding its DB connection."""
        self.bind_epoch()
        head, _ = self.checkpoint(tenant, run)
        return max(0 if head is None else head["sequence"], self._acknowledged_floor(tenant, run))

    @staticmethod
    def _check_source_head(source_head: int, minimum_source_head: int) -> None:
        if (
            type(source_head) is not int
            or not 0 <= source_head <= _MAX_SEQUENCE
            or type(minimum_source_head) is not int
            or minimum_source_head < 0
            or source_head < minimum_source_head
        ):
            raise WitnessConflict("source head lost previously acknowledged events")

    def acknowledge_page(
        self,
        tenant: str,
        run: str,
        events: tuple[WitnessEvent, ...],
        *,
        after_sequence: int,
        source_head: int,
        limit: int,
        minimum_source_head: int,
    ) -> None:
        """Check the exact requested range from one source statement snapshot.

        A cursor beyond the current head still legitimately returns an empty
        page. A missing first/tail/all event within the requested range cannot.
        No old prefix is scanned or declared acknowledged by this page.
        """
        if type(after_sequence) is not int or after_sequence < 0 or not 1 <= limit <= 5000:
            raise WitnessUnavailable("event page cursor or bound is invalid")
        self._check_source_head(source_head, minimum_source_head)
        expected_end = min(source_head, after_sequence + limit)
        expected = tuple(range(after_sequence + 1, max(after_sequence, expected_end) + 1))
        if tuple(event.sequence for event in events) != expected:
            raise WitnessConflict("source event page is missing its requested first/tail/range")
        self.acknowledge_events(tenant, run, events)

    def acknowledge_events(self, tenant: str, run: str, events: tuple[WitnessEvent, ...]) -> None:
        """ACK exact consumer events; this makes no complete API-page assertion."""
        self.bind_epoch()
        if len(events) > 5000:
            raise WitnessUnavailable("event ACK page exceeds the existing API bound")
        sequences = tuple(event.sequence for event in events)
        if any(type(n) is not int or not 1 <= n <= _MAX_SEQUENCE for n in sequences) or any(
            right != left + 1 for left, right in pairwise(sequences)
        ):
            raise WitnessConflict("returned event page is not a contiguous ordered range")
        for event in events:
            self._acknowledge_event(tenant, run, event)
        if events:
            sequence = events[-1].sequence
            body = self._seal(
                {
                    "schema_version": 1,
                    "product_revision": self.product_revision,
                    "key_version": self.key_version,
                    "run_hmac": self.identifier(tenant + "/" + run),
                    "sequence": sequence,
                }
            )
            key = (
                self.prefix(tenant, run)
                + f"acknowledged-heads/{_MAX_SEQUENCE - sequence:020d}.json"
            )
            old = self._read(key)
            if old is None:
                try:
                    old = self._put(key, body, expected_etag=None)
                except WitnessConflict:
                    old = self._read(key)
            if (
                old is None
                or not hmac.compare_digest(old.body, body)
                or self._acknowledged_floor(tenant, run) < sequence
            ):
                raise WitnessUnavailable("event ACK floor is not independently visible")

    def acknowledge_projection(
        self, tenant: str, run: str, sequence: int, projection: dict[str, object]
    ) -> None:
        """Only state facts that require a new event are stable at this sequence."""
        self.bind_epoch()
        body = self._seal(
            {
                "schema_version": 1,
                "product_revision": self.product_revision,
                "key_version": self.key_version,
                "run_hmac": self.identifier(tenant + "/" + run),
                "sequence": sequence,
                "projection_digest": self.identifier(canonical(projection).decode()),
            }
        )
        key = self.prefix(tenant, run) + f"projections/{sequence:020d}.json"
        existing = self._read(key)
        if existing is None:
            try:
                existing = self._put(key, body, expected_etag=None)
            except WitnessConflict:
                existing = self._read(key)
        if existing is None or not hmac.compare_digest(existing.body, body):
            raise WitnessConflict("same Run Event cursor has a different state projection")

    def _acknowledge_event(self, tenant: str, run: str, event: WitnessEvent) -> None:
        body = self._seal(
            {
                "schema_version": 1,
                "product_revision": self.product_revision,
                "key_version": self.key_version,
                "run_hmac": self.identifier(tenant + "/" + run),
                "sequence": event.sequence,
                "event_digest": self.identifier(canonical(event.content).decode()),
            }
        )
        key = self.prefix(tenant, run) + f"acknowledged/{event.sequence:020d}.json"
        existing = self._read(key)
        if existing is None:
            try:
                existing = self._put(key, body, expected_etag=None)
            except WitnessConflict:
                existing = self._read(key)
        if existing is None or not hmac.compare_digest(existing.body, body):
            raise WitnessConflict("acknowledged Run Event sequence content changed")

    def ensure_segment(
        self,
        tenant: str,
        run: str,
        *,
        source_head: int,
        events: tuple[WitnessEvent, ...],
        previous: tuple[dict[str, Any] | None, StoredObject | None],
        anchor: WitnessEvent | None,
        actual_source_head: int | None = None,
        minimum_source_head: int = 0,
    ) -> int:
        """Input rows are read in the original RLS scope, after the source commit."""
        self._check_source_head(
            source_head if actual_source_head is None else actual_source_head, minimum_source_head
        )
        head, _stored = previous
        old_sequence = 0 if head is None else head["sequence"]
        if source_head < old_sequence:
            raise WitnessConflict("source Run lost previously witnessed events")
        if source_head - old_sequence > self.max_segment:
            raise WitnessBackfillRequired("Run Event witness needs bounded background recovery")
        if head is not None and old_sequence:
            if anchor is None or anchor.sequence != old_sequence:
                raise WitnessConflict("source witness anchor is missing")
            digest = self.identifier(canonical(anchor.content).decode())
            if not hmac.compare_digest(digest, head["event_digest"]):
                raise WitnessConflict("source witness anchor content changed")
        if tuple(e.sequence for e in events) != tuple(range(old_sequence + 1, source_head + 1)):
            raise WitnessConflict("source Run Event prefix is missing or duplicated")
        if not events:
            return source_head
        prefix = self.prefix(tenant, run)
        previous_digest = "0" * 64 if head is None else head["event_digest"]
        for item in events:
            self._acknowledge_event(tenant, run, item)
            event_digest = self.identifier(canonical(item.content).decode())
            body = self._seal(
                {
                    "schema_version": 1,
                    "product_revision": self.product_revision,
                    "key_version": self.key_version,
                    "run_hmac": self.identifier(tenant + "/" + run),
                    "sequence": item.sequence,
                    "event_digest": event_digest,
                    "previous_event_digest": previous_digest,
                }
            )
            key = prefix + f"events/{item.sequence:020d}.json"
            existing = self._read(key)
            if existing is None:
                try:
                    existing = self._put(key, body, expected_etag=None)
                except WitnessConflict:
                    existing = self._read(key)
            if existing is None or not hmac.compare_digest(existing.body, body):
                raise WitnessConflict("Run Event sequence already has different witness content")
            previous_digest = event_digest
        next_body = self._seal(
            {
                "schema_version": 1,
                "product_revision": self.product_revision,
                "key_version": self.key_version,
                "run_hmac": self.identifier(tenant + "/" + run),
                "sequence": source_head,
                "event_digest": previous_digest,
            }
        )
        key = prefix + f"heads/{_MAX_SEQUENCE - source_head:020d}.json"
        existing = self._read(key)
        if existing is None:
            try:
                existing = self._put(key, next_body, expected_etag=None)
            except WitnessConflict:
                existing = self._read(key)
        if existing is None or not hmac.compare_digest(existing.body, next_body):
            raise WitnessConflict("same sequence has a different immutable checkpoint")
        current, _ = self.checkpoint(tenant, run)
        if current is None or current["sequence"] < source_head:
            raise WitnessUnavailable("new checkpoint is not independently visible")
        return source_head

    def _seal(self, payload: dict[str, object]) -> bytes:
        return canonical({**payload, "mac": self.identifier(canonical(payload).decode())})

    @staticmethod
    def _decode(body: bytes) -> dict[str, Any]:
        if len(body) > 8192:
            raise WitnessConflict("witness checkpoint exceeds bound")
        try:
            value = json.loads(body)
        except (ValueError, UnicodeError):
            raise WitnessConflict("witness checkpoint is not canonical JSON") from None
        if not isinstance(value, dict) or canonical(value) != body:
            raise WitnessConflict("witness checkpoint is not canonical JSON")
        return value


class S3WitnessStore:
    """Optional WORM adapter using an explicit client; no ambient credentials.

    ObjectLock is this adapter's implementation choice, not a new universal SLO gate.
    Other stores must prove equivalent independent durability and append-only denial.
    """

    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        prefix: str,
        retention_days: int = 45,
        maximum_body_bytes: int = 8192,
    ) -> None:
        if (
            not bucket
            or not prefix
            or prefix.startswith("/")
            or ".." in prefix.split("/")
            or type(retention_days) is not int
            or not 45 <= retention_days <= 2555
            or type(maximum_body_bytes) is not int
            or not 8192 <= maximum_body_bytes <= 1024 * 1024
        ):
            raise ValueError("witness bucket prefix or retention is invalid")
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.retention_days = retention_days
        self.maximum_body_bytes = maximum_body_bytes

    def preflight(self) -> None:
        try:
            versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
            lock = self.client.get_object_lock_configuration(Bucket=self.bucket)[
                "ObjectLockConfiguration"
            ]
            if versioning.get("Status") != "Enabled" or lock.get("ObjectLockEnabled") != "Enabled":
                raise WitnessUnavailable("witness bucket needs actual versioning and ObjectLock")
        except WitnessUnavailable:
            raise
        except Exception:  # noqa: BLE001 -- SDK boundary; redact private request context
            raise WitnessUnavailable("witness storage qualification failed") from None

    def first(self, prefix: str) -> tuple[str, StoredObject] | None:
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket,
                Prefix=self.prefix + prefix,
                MaxKeys=1,
            )
            rows = response.get("Contents", [])
            if len(rows) > 1:
                raise WitnessUnavailable("checkpoint listing exceeded its fixed bound")
            if not rows:
                return None
            key = rows[0]["Key"]
            if not isinstance(key, str) or not key.startswith(self.prefix + prefix):
                raise WitnessUnavailable("checkpoint listing escaped its authorized prefix")
            relative = key[len(self.prefix) :]
            result = self.read(relative)
            if result is None:
                raise WitnessUnavailable("listed immutable checkpoint is missing")
            return relative, result
        except WitnessUnavailable:
            raise
        except Exception:  # noqa: BLE001 -- redact SDK credentials and signed requests
            raise WitnessUnavailable("bounded immutable checkpoint discovery failed") from None

    def read(self, key: str) -> StoredObject | None:
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=self.prefix + key)
        except Exception as error:  # noqa: BLE001 -- redact SDK credentials
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if code in {"NoSuchKey", "404", "NotFound"}:
                return None
            raise WitnessUnavailable("witness object metadata could not be read") from None
        version, etag = head.get("VersionId"), head.get("ETag")
        until = head.get("ObjectLockRetainUntilDate")
        if (
            not version
            or version == "null"
            or not etag
            or head.get("ObjectLockMode") != "COMPLIANCE"
            or not isinstance(until, datetime)
            or until.tzinfo is None
            or until <= datetime.now(UTC)
        ):
            raise WitnessUnavailable("witness object lacks an immutable retained version")
        try:
            response = self.client.get_object(
                Bucket=self.bucket,
                Key=self.prefix + key,
                VersionId=version,
            )
            body = response["Body"]
            try:
                payload = body.read(self.maximum_body_bytes + 1)
            finally:
                body.close()
            if len(payload) > self.maximum_body_bytes or response.get("VersionId") != version:
                raise WitnessUnavailable("witness readback is oversized or changed version")
            return StoredObject(payload, etag, version)
        except WitnessUnavailable:
            raise
        except Exception:  # noqa: BLE001 -- redact SDK credentials
            raise WitnessUnavailable("version-pinned witness object could not be read") from None

    def conditional_put(self, key: str, body: bytes, *, expected_etag: str | None) -> StoredObject:
        if len(body) > self.maximum_body_bytes:
            raise WitnessUnavailable("witness object exceeds bound")
        parameters: dict[str, object] = {
            "Bucket": self.bucket,
            "Key": self.prefix + key,
            "Body": body,
            "ContentType": "application/json",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": datetime.now(UTC) + timedelta(days=self.retention_days),
        }
        parameters["IfNoneMatch" if expected_etag is None else "IfMatch"] = (
            "*" if expected_etag is None else expected_etag
        )
        try:
            self.client.put_object(**parameters)
        except Exception:  # noqa: BLE001 -- explicit SDK client; redact credentials
            # Never repeat an uncertain write. A definite existing immutable key
            # is independently read back; retained stores can deny any overwrite.
            result = self.read(key)
            if result is not None:
                if hmac.compare_digest(result.body, body):
                    return result
                raise WitnessConflict("stable witness key already has different content") from None
            raise WitnessUnavailable(
                "witness write outcome is uncertain; verify stable key"
            ) from None
        result = self.read(key)
        if result is None or result.body != body:
            raise WitnessUnavailable("witness write has no matching immutable readback")
        return result
