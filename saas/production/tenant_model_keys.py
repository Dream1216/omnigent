"""Deployment-owned tenant key bindings; never derive trust from a bearer claim."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

from saas.runner_adapter.platform_model_gateway import (
    PlatformModelGatewayClaims,
    PlatformModelGatewayTokenAuthority,
    PlatformModelGatewayTokenError,
)

_FILE_ENV = "OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_FILE"
_HASH_ENV = "OMNIGENT_SAAS_TENANT_MODEL_BINDINGS_SHA256"


@dataclass(frozen=True)
class TenantModelKeyBinding:
    tenant_id: UUID
    workspace_id: int
    sandbox_secret_name: str
    gateway_key_file: Path


def _read_file(path: Path, *, private: bool, maximum: int) -> bytes:
    """Bound and identity-check one deployment-owned regular file."""

    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Tenant model authority file is invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            mask = 0o077 if private else 0o022
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & mask
                or not 0 < before.st_size <= maximum
            ):
                raise ValueError("Tenant model authority file is invalid")
            chunks = bytearray()
            while len(chunks) <= maximum:
                chunk = os.read(fd, min(4096, maximum + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            expected = tuple(getattr(before, field) for field in fields)
            if len(chunks) != before.st_size or any(
                tuple(getattr(after, field) for field in fields) != expected
                for after in (os.fstat(fd), path.lstat())
            ):
                raise ValueError("Tenant model authority file changed")
            return bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise ValueError("Tenant model authority file is unavailable") from None


def load_tenant_model_bindings(source: Mapping[str, str]) -> tuple[TenantModelKeyBinding, ...]:
    """Load an explicitly hash-pinned, bounded tenant allowlist without keys."""

    filename, expected = source.get(_FILE_ENV), source.get(_HASH_ENV)
    if filename is None and expected is None:
        return ()
    if not filename or not expected or len(expected) != 64:
        raise ValueError("Tenant model bindings require a file and SHA-256")
    raw = _read_file(Path(filename), private=False, maximum=32768)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Tenant model bindings digest mismatch")
    try:
        document = json.loads(raw)
        canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if (
            raw != canonical
            or not isinstance(document, dict)
            or set(document) != {"schema_version", "bindings"}
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or not isinstance(document["bindings"], list)
            or not 1 <= len(document["bindings"]) <= 32
        ):
            raise ValueError
        result = []
        for row in document["bindings"]:
            if not isinstance(row, dict) or set(row) != {
                "tenant_id",
                "workspace_id",
                "sandbox_secret_name",
                "gateway_key_file",
            }:
                raise ValueError
            tenant = UUID(row["tenant_id"])
            key_file = Path(row["gateway_key_file"])
            if (
                tenant.int == 0
                or str(tenant) != row["tenant_id"]
                or type(row["workspace_id"]) is not int
                or row["workspace_id"] <= 0
                or row["sandbox_secret_name"] != f"omnigent-sandbox-model-{tenant.hex}"
                or not key_file.is_absolute()
                or ".." in key_file.parts
            ):
                raise ValueError
            result.append(
                TenantModelKeyBinding(
                    tenant, row["workspace_id"], row["sandbox_secret_name"], key_file
                )
            )
        for attr in ("tenant_id", "workspace_id", "sandbox_secret_name", "gateway_key_file"):
            if len({getattr(row, attr) for row in result}) != len(result):
                raise ValueError
        return tuple(result)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Tenant model bindings are invalid") from None


class TenantModelTokenVerifier:
    """Select only a configured verifier, then validate its signature and tenant."""

    def __init__(
        self,
        legacy: PlatformModelGatewayTokenAuthority,
        legacy_key: bytes,
        bindings: tuple[TenantModelKeyBinding, ...],
    ) -> None:
        authorities = {legacy.tenant_id: legacy}
        key_hashes = {hashlib.sha256(legacy_key).digest()}
        for binding in bindings:
            key = _read_file(binding.gateway_key_file, private=True, maximum=4096).rstrip(b"\r\n")
            digest = hashlib.sha256(key).digest()
            if (
                binding.tenant_id in authorities
                or digest in key_hashes
                or not 32 <= len(key) <= 4096
                or b"\x00" in key
            ):
                raise ValueError("Tenant model signing authority must be independent")
            authorities[binding.tenant_id] = PlatformModelGatewayTokenAuthority(
                signing_key=key,
                tenant_id=binding.tenant_id,
            )
            key_hashes.add(digest)
        self._authorities = MappingProxyType(authorities)

    def validate(self, token: str, *, now: int | None = None) -> PlatformModelGatewayClaims:
        try:
            if len(token) > 8192:
                raise ValueError
            payload = token.split(".", 1)[0]
            document = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            tenant = UUID(document["tid"])
            verifier = self._authorities[tenant]
        except (ValueError, TypeError, KeyError, AttributeError):
            raise PlatformModelGatewayTokenError("invalid tenant authority") from None
        return verifier.validate(token, now=now)
