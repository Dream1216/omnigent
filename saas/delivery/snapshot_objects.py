"""Private DCP object authority using immutable SSE-C S3 objects.

Only the dedicated client-authenticated TLS listener registers these routes.
Allocation additionally resolves the current actor/project and membership from
the application database. S3 credentials and the keyring never leave this service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlsplit
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from saas.control_plane.authorization import ProjectAuthorizer

if TYPE_CHECKING:
    from saas.delivery.authorization import DeliveryAuthorization

_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_CONTENT_TYPE = "application/vnd.omnigent.source-snapshot.v1.tar+zstd"
_REVOKED_TYPE = "application/vnd.omnigent.snapshot-upload-revoked.v1"
_MAX_BYTES = 1024 * 1024 * 1024


def _denied(code: str, status: int = 403) -> HTTPException:
    return HTTPException(status, detail={"code": code})


def _private_bytes(path: Path) -> bytes:
    from saas.production.server_config import _absolute_regular_file

    checked = _absolute_regular_file(str(path), name="Snapshot authority secret", owner_only=True)
    descriptor = os.open(checked, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o077
            or not 0 < before.st_size <= 16 * 1024
        ):
            raise ValueError("invalid private Snapshot authority file")
        value = bytearray()
        while len(value) <= 16 * 1024:
            chunk = os.read(descriptor, min(4096, 16 * 1024 + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
        after = os.fstat(descriptor)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns)

        if identity(before) != identity(after) or len(value) != before.st_size:
            raise ValueError("Snapshot authority file changed during read")
        return bytes(value)
    finally:
        os.close(descriptor)


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Snapshot authority setting")
        result[key] = value
    return result


@dataclass(frozen=True)
class SnapshotObjectSettings:
    bearer_token_file: Path = field(repr=False)
    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)
    ttl_seconds: int = 300
    max_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))
        if (
            not self.bearer_token_file.is_absolute()
            or not 1 <= len(self.keys) <= 8
            or self.active_key_id not in self.keys
            or any(_KEY_ID.fullmatch(k) is None or len(v) != 32 for k, v in self.keys.items())
            or type(self.ttl_seconds) is not int
            or not 30 <= self.ttl_seconds <= 600
            or type(self.max_bytes) is not int
            or not 1 <= self.max_bytes <= _MAX_BYTES
        ):
            raise ValueError("invalid Snapshot object authority settings")
        self.bearer_token()

    def bearer_token(self) -> bytes:
        value = _private_bytes(self.bearer_token_file).strip()
        if not 32 <= len(value) <= 8192 or any(not 32 < byte < 127 for byte in value):
            raise ValueError("invalid private Snapshot authority token")
        return value

    @classmethod
    def from_file(cls, path: Path) -> SnapshotObjectSettings:
        try:
            value = json.loads(_private_bytes(path), object_pairs_hook=_unique_fields)
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "bearer_token_file",
                "active_key_id",
                "keys",
                "ttl_seconds",
                "max_bytes",
            }:
                raise ValueError("invalid authority settings document")
            if value["schema_version"] != "omnigent.saas.snapshot-object-authority/v1":
                raise ValueError("unknown authority settings version")
            return cls(
                bearer_token_file=Path(value["bearer_token_file"]),
                active_key_id=value["active_key_id"],
                keys={
                    key: _private_bytes(Path(filename)) for key, filename in value["keys"].items()
                },
                ttl_seconds=value["ttl_seconds"],
                max_bytes=value["max_bytes"],
            )
        except (ValueError, TypeError, KeyError, OSError, AttributeError, RecursionError):
            raise ValueError("invalid private Snapshot object authority configuration") from None


class SnapshotObjectIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tenant_id: UUID
    project_id: UUID
    actor_id: UUID
    membership_version: int = Field(ge=1, strict=True)
    token_id: str = Field(min_length=1, max_length=128)


class SnapshotObjectRequest(BaseModel):
    # The producer validates the fields it consumes; future exporter options
    # cannot select a bucket, key, principal, credential or encryption policy.
    model_config = ConfigDict(extra="ignore", frozen=True)
    space_id: str
    environment_id: str
    build_id: str
    max_bytes: int = Field(ge=1, le=_MAX_BYTES, strict=True)

    @field_validator("space_id", "environment_id", "build_id")
    @classmethod
    def identifier(cls, value: str) -> str:
        if _OPAQUE.fullmatch(value) is None or ".." in value:
            raise ValueError("invalid Snapshot object identifier")
        return value


class SnapshotObjectAllocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: SnapshotObjectIdentity
    request: SnapshotObjectRequest


class SnapshotObjectReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    object_ref: str = Field(min_length=1, max_length=1024)


class SnapshotObjectAuthority:
    def __init__(
        self,
        authority: DeliveryAuthorization,
        settings: SnapshotObjectSettings,
        *,
        client: Any,
        artifact_store_uri: str,
        endpoint_url: str,
    ):
        uri, endpoint = urlsplit(artifact_store_uri), urlsplit(endpoint_url)
        if (
            uri.scheme != "s3"
            or not uri.netloc
            or uri.username
            or uri.password
            or uri.query
            or uri.fragment
            or endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
            or endpoint.path not in {"", "/"}
        ):
            raise ValueError("invalid configured Snapshot object storage")
        prefix = uri.path.strip("/")
        if prefix and any(part in {"", ".", ".."} for part in prefix.split("/")):
            raise ValueError("invalid Snapshot object prefix")
        self.authority, self.settings, self.client = authority, settings, client
        self.bucket = uri.netloc
        self.prefix = (prefix + "/" if prefix else "") + "executor_storage/dcp-source-snapshots/v1"
        self.endpoint = endpoint

    def authenticate(self, authorization: str | None) -> None:
        if authorization is None or not authorization.startswith("Bearer "):
            raise _denied("snapshot_object_authentication_required", 401)
        supplied = authorization.removeprefix("Bearer ").encode()
        if len(supplied) > 8192 or not hmac.compare_digest(supplied, self.settings.bearer_token()):
            raise _denied("snapshot_object_authentication_required", 401)

    def _authorize(self, body: SnapshotObjectAllocation) -> None:
        identity, request = body.identity, body.request
        project = next(
            (
                p
                for p in self.authority.config.projects
                if p.tenant_id == identity.tenant_id and p.project_id == identity.project_id
            ),
            None,
        )
        if project is None or request.space_id != str(project.space_id):
            raise _denied("snapshot_object_scope_denied")
        if request.environment_id == project.preview_environment:
            action = "preview.open"
        elif request.environment_id == project.production_environment:
            action = "environment.manage"
        else:
            raise _denied("snapshot_object_scope_denied")
        current = self.authority.resolver.resolve_request_context(
            actor_id=identity.actor_id,
            tenant_id=identity.tenant_id,
            space_id=project.space_id,
            trace_id=uuid4().hex,
        )
        authorizer = ProjectAuthorizer(self.authority.sessions)
        for permission in ("project.content.read", "run.create", action):
            current = authorizer.bind_project_context(
                current, action=permission, project_id=project.project_id
            )
        if current.tenant_membership_version != identity.membership_version:
            raise _denied("snapshot_object_authorization_changed")
        if request.max_bytes > self.settings.max_bytes:
            raise _denied("snapshot_object_size_limit", 413)

    def _customer_key(self, key: str, key_id: str) -> bytes:
        return hmac.digest(
            self.settings.keys[key_id],
            b"omnigent.snapshot-object.ssec/v1\0" + self.bucket.encode() + b"\0" + key.encode(),
            "sha256",
        )

    def _encryption(self, key: str, key_id: str) -> dict[str, Any]:
        return {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": self._customer_key(key, key_id),
        }

    def _reference(self, object_ref: str) -> tuple[str, list[str]]:
        parsed = urlsplit(object_ref)
        prefix = "/" + self.prefix + "/"
        if (
            parsed.scheme != "s3"
            or parsed.netloc != self.bucket
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith(prefix)
        ):
            raise _denied("snapshot_object_unavailable", 404)
        parts = parsed.path.removeprefix(prefix).split("/")
        if (
            len(parts) != 5
            or parts[0] not in self.settings.keys
            or any(_OPAQUE.fullmatch(p) is None or ".." in p for p in parts)
            or re.fullmatch(r"[0-9a-f]{32}", parts[-1]) is None
        ):
            raise _denied("snapshot_object_unavailable", 404)
        if object_ref != "s3://" + self.bucket + prefix + "/".join(parts):
            raise _denied("snapshot_object_unavailable", 404)
        for value in parts[1:3]:
            try:
                if str(UUID(value)) != value:
                    raise ValueError("noncanonical principal")
            except ValueError:
                raise _denied("snapshot_object_unavailable", 404) from None
        return parsed.path[1:], parts

    @staticmethod
    def _status(error: Exception) -> int | None:
        response = getattr(error, "response", {})
        return (
            response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if isinstance(response, dict)
            else None
        )

    def allocate(self, body: SnapshotObjectAllocation) -> dict[str, Any]:
        self._authorize(body)
        identity, request = body.identity, body.request
        kid = self.settings.active_key_id
        key = (
            f"{self.prefix}/{kid}/{identity.tenant_id}/{identity.project_id}/"
            f"{request.build_id}/{secrets.token_hex(16)}"
        )
        metadata = {
            "tenant-id": str(identity.tenant_id),
            "project-id": str(identity.project_id),
            "build-id": request.build_id,
            "authority-key-id": kid,
            "max-bytes": str(request.max_bytes),
        }
        parameters = {
            "Bucket": self.bucket,
            "Key": key,
            "ContentType": _CONTENT_TYPE,
            "Metadata": metadata,
            "IfNoneMatch": "*",
            **self._encryption(key, kid),
        }
        url = self.client.generate_presigned_url(
            "put_object", Params=parameters, ExpiresIn=self.settings.ttl_seconds, HttpMethod="PUT"
        )
        target = urlsplit(url)
        if (
            (target.scheme, target.netloc) != (self.endpoint.scheme, self.endpoint.netloc)
            or target.username
            or target.password
            or target.fragment
            or target.path != "/" + quote(self.bucket, safe="") + "/" + quote(key, safe="/")
        ):
            raise _denied("snapshot_object_target_invalid", 503)
        customer = self._customer_key(key, kid)
        headers = {
            "Content-Type": _CONTENT_TYPE,
            "If-None-Match": "*",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": base64.b64encode(customer).decode(),
            "x-amz-server-side-encryption-customer-key-md5": base64.b64encode(
                hashlib.md5(customer, usedforsecurity=False).digest()
            ).decode(),
            **{"x-amz-meta-" + name: value for name, value in metadata.items()},
        }
        # Only the authenticated private response may serialize these ephemeral secrets.
        return {
            "object_ref": "s3://" + self.bucket + "/" + key,
            "put_url": url,
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=self.settings.ttl_seconds)
            ).isoformat(),
            "max_bytes": request.max_bytes,
        }

    def _open(self, object_ref: str) -> tuple[dict[str, Any], Any, int]:
        key, parts = self._reference(object_ref)
        try:
            response = self.client.get_object(
                Bucket=self.bucket, Key=key, **self._encryption(key, parts[0])
            )
        except Exception as error:
            if self._status(error) in {400, 403, 404}:
                raise _denied("snapshot_object_unavailable", 404) from None
            raise
        body = response["Body"]
        try:
            metadata = response.get("Metadata", {})
            expected = {
                "authority-key-id": parts[0],
                "tenant-id": parts[1],
                "project-id": parts[2],
                "build-id": parts[3],
            }
            size, maximum = response.get("ContentLength"), int(metadata.get("max-bytes", "0"))
            customer = self._customer_key(key, parts[0])
            if (
                type(size) is not int
                or not 0 < size <= maximum <= self.settings.max_bytes
                or response.get("ContentType") != _CONTENT_TYPE
                or response.get("SSECustomerAlgorithm") != "AES256"
                or response.get("SSECustomerKeyMD5")
                != base64.b64encode(hashlib.md5(customer, usedforsecurity=False).digest()).decode()
                or any(metadata.get(k) != v for k, v in expected.items())
            ):
                raise _denied("snapshot_object_verification_failed", 409)
            return response, body, size
        except BaseException:
            body.close()
            raise

    @staticmethod
    def _chunks(body: Any, size: int) -> Iterator[bytes]:
        count = 0
        try:
            while chunk := body.read(65536):
                count += len(chunk)
                if not isinstance(chunk, bytes) or count > size:
                    raise ValueError("Snapshot object stream length mismatch")
                yield chunk
            if count != size:
                raise ValueError("Snapshot object stream ended before declared length")
        except Exception:  # noqa: BLE001 - provider stream diagnostics may contain credentials.
            raise RuntimeError("snapshot_object_stream_unavailable") from None
        finally:
            body.close()

    def head(self, object_ref: str) -> dict[str, Any]:
        response, body, size = self._open(object_ref)
        digest = hashlib.sha256()
        for chunk in self._chunks(body, size):
            digest.update(chunk)
        metadata = response["Metadata"]
        return {
            "object_ref": object_ref,
            "size": size,
            "archive_digest": "sha256:" + digest.hexdigest(),
            "tenant_id": metadata["tenant-id"],
            "project_id": metadata["project-id"],
            "build_id": metadata["build-id"],
            "encrypted": True,
        }

    def stream(self, object_ref: str) -> Iterator[bytes]:
        _response, body, size = self._open(object_ref)
        return self._chunks(body, size)

    def revoke(self, object_ref: str) -> None:
        key, parts = self._reference(object_ref)
        try:
            # A tombstone fences an unused signed PUT; an existing immutable
            # object already makes its If-None-Match signature unusable.
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=b"",
                ContentType=_REVOKED_TYPE,
                IfNoneMatch="*",
                **self._encryption(key, parts[0]),
            )
        except Exception as error:
            if self._status(error) != 412:
                raise
