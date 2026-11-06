"""Server-signed model admission context bound to one managed Host credential."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any
from uuid import UUID

from saas.compatibility.runtime_partition import RuntimeContext

_MAX_TTL_S = 7200
_DOMAIN = b"omnigent-aliyun-host-model:v1\x00"
_UUID_FIELDS = (
    "actor_id",
    "tenant_id",
    "space_id",
    "project_id",
    "runtime_partition_id",
    "placement_id",
)
_INT_FIELDS = (
    "user_security_version",
    "tenant_membership_version",
    "space_membership_version",
    "placement_generation",
    "binding_generation",
    "physical_workspace_id",
)
_TEXT_FIELDS = (
    "data_region",
    "runtime_user_key",
    "runtime_type",
    "source_revision",
    "adapter_contract_version",
    "trace_id",
)


class HostModelLeaseError(PermissionError):
    """The launch context is invalid, expired, or bound to another Host."""


@dataclass(frozen=True)
class HostModelLease:
    host_id: str
    runtime: RuntimeContext
    issued_at: int
    expires_at: int


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _runtime(document: Any) -> RuntimeContext:
    if not isinstance(document, dict) or set(document) != set(
        _UUID_FIELDS + _INT_FIELDS + _TEXT_FIELDS
    ):
        raise ValueError("invalid runtime fields")
    result: dict[str, Any] = dict(document)
    for field in _UUID_FIELDS:
        raw = document[field]
        if field == "project_id" and raw is None:
            continue
        if not isinstance(raw, str):
            raise ValueError("invalid runtime identifier")
        parsed = UUID(raw)
        if parsed.int == 0 or str(parsed) != raw:
            raise ValueError("invalid runtime identifier")
        result[field] = parsed
    for field in _INT_FIELDS:
        if type(document[field]) is not int or not 0 < document[field] < 2**63:
            raise ValueError("invalid runtime generation")
    for field in _TEXT_FIELDS:
        value = document[field]
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 512
            or value != value.strip()
            or "\x00" in value
        ):
            raise ValueError("invalid runtime text")
    return RuntimeContext(**result)


def _host_token(host_id: str, launch_token: str) -> str:
    if (
        not isinstance(host_id, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", host_id) is None
        or not isinstance(launch_token, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{32,512}", launch_token) is None
    ):
        raise HostModelLeaseError("Host model credential is invalid")
    return sha256(launch_token.encode()).hexdigest()


class HostModelLeaseAuthority:
    """Keep the signing key server-side; a lease cannot replace the Host token."""

    def __init__(self, signing_key: bytes) -> None:
        if not isinstance(signing_key, bytes) or not 32 <= len(signing_key) <= 4096:
            raise ValueError("Host model lease authority is invalid")
        self._key = signing_key

    def issue(
        self,
        *,
        host_id: str,
        launch_token: str,
        runtime: RuntimeContext,
        ttl_seconds: int,
        now: int | None = None,
    ) -> str:
        digest = _host_token(host_id, launch_token)
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= _MAX_TTL_S:
            raise ValueError("Host model lease lifetime is invalid")
        issued_at = int(time.time()) if now is None else now
        if type(issued_at) is not int or issued_at <= 0:
            raise ValueError("Host model lease time is invalid")
        values: dict[str, Any] = dict(asdict(runtime))
        for field in _UUID_FIELDS:
            if values[field] is not None:
                values[field] = str(values[field])
        _runtime(values)
        encoded = _b64(
            _json(
                {
                    "v": 1,
                    "host": host_id,
                    "token_digest": digest,
                    "iat": issued_at,
                    "exp": issued_at + ttl_seconds,
                    "runtime": values,
                }
            )
        )
        signature = _b64(hmac.new(self._key, _DOMAIN + encoded.encode(), sha256).digest())
        return f"{encoded}.{signature}"

    def verify(
        self,
        lease: str,
        *,
        host_id: str,
        launch_token: str,
        now: int | None = None,
    ) -> HostModelLease:
        digest = _host_token(host_id, launch_token)
        try:
            if not isinstance(lease, str) or not 1 <= len(lease) <= 16384:
                raise ValueError("invalid lease size")
            encoded, signature = lease.split(".")
            expected = _b64(hmac.new(self._key, _DOMAIN + encoded.encode(), sha256).digest())
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid lease signature")
            raw = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            document = json.loads(raw)
            if (
                not isinstance(document, dict)
                or set(document) != {"v", "host", "token_digest", "iat", "exp", "runtime"}
                or _json(document) != raw
                or type(document["v"]) is not int
                or document["v"] != 1
                or document["host"] != host_id
                or not isinstance(document["token_digest"], str)
                or not hmac.compare_digest(document["token_digest"], digest)
            ):
                raise ValueError("invalid lease binding")
            issued_at, expires_at = document["iat"], document["exp"]
            current = int(time.time()) if now is None else now
            if (
                type(current) is not int
                or current <= 0
                or type(issued_at) is not int
                or type(expires_at) is not int
                or issued_at > current + 30
                or issued_at <= 0
                or not 60 <= expires_at - issued_at <= _MAX_TTL_S
                or expires_at <= current
            ):
                raise ValueError("invalid lease lifetime")
            runtime = _runtime(document["runtime"])
        except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
            raise HostModelLeaseError("Host model lease is invalid or expired") from None
        return HostModelLease(host_id, runtime, issued_at, expires_at)
