"""Opaque, replica-verifiable short-lived authorization/runtime snapshots."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Never
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from saas.compatibility import RuntimeContext
from saas.control_plane.lifecycle import ValidatedAuthSession
from saas.control_plane.permissions import POLICY_VERSION

_MAX_SNAPSHOT_TTL = timedelta(seconds=60)
_HEADER_TYPE = "saas-context-snapshot+jwe"


class ContextSnapshotError(PermissionError):
    """Stable fail-closed error raised for invalid or stale snapshots."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class ControlPlaneDependencyUnavailable(RuntimeError):
    """Explicitly classified control-plane availability failure."""

    code = "control_plane_unavailable"


class ControlPlaneAvailabilityGate:
    """Injectable circuit state used by replicas and deterministic fault tests."""

    def __init__(self, *, available: bool = True) -> None:
        self._available = available

    @property
    def available(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available

    def require_available(self) -> None:
        if not self._available:
            raise ControlPlaneDependencyUnavailable("control plane is unavailable")


@dataclass(frozen=True, slots=True)
class ContextSnapshotPolicy:
    """Shared replica key ring and strict lifetime/issuer contract."""

    active_key_id: str
    keys: Mapping[str, bytes]
    issuer: str
    audience: str
    ttl: timedelta = _MAX_SNAPSHOT_TTL
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def __post_init__(self) -> None:
        if not self.active_key_id or self.active_key_id not in self.keys:
            raise ValueError("active snapshot key id must exist in the key ring")
        if not self.issuer.strip() or not self.audience.strip():
            raise ValueError("snapshot issuer and audience must not be empty")
        if self.ttl <= timedelta(0) or self.ttl > _MAX_SNAPSHOT_TTL:
            raise ValueError("context snapshot TTL must be between 1 and 60 seconds")
        if any(not key_id or len(key) < 32 for key_id, key in self.keys.items()):
            raise ValueError("every context snapshot key must contain at least 32 bytes")
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))


@dataclass(frozen=True, slots=True)
class IssuedContextSnapshot:
    """Opaque token plus non-sensitive selection metadata."""

    token: str
    issued_at: datetime
    expires_at: datetime
    tenant_id: str
    space_id: str


@dataclass(frozen=True, slots=True)
class VerifiedContextSnapshot:
    """Authenticated session and RuntimeContext recovered by another replica."""

    session: ValidatedAuthSession
    runtime_context: RuntimeContext
    issued_at: datetime
    expires_at: datetime
    policy_version: str
    snapshot_id: str


class ContextSnapshotService:
    """Issue encrypted, signed, token-bound snapshots with no database dependency."""

    def __init__(self, policy: ContextSnapshotPolicy) -> None:
        self._policy = policy

    def issue(
        self,
        *,
        auth_token: str,
        session: ValidatedAuthSession,
        runtime_context: RuntimeContext,
    ) -> IssuedContextSnapshot:
        if not auth_token:
            self._deny("snapshot_token_binding_invalid", "authentication token is required")
        if session.user_id != runtime_context.actor_id:
            self._deny("snapshot_actor_mismatch", "session and runtime actors differ")
        if session.security_version != runtime_context.user_security_version:
            self._deny("snapshot_security_version_stale", "session security version is stale")

        issued_at = self._now()
        expires_at = min(issued_at + self._policy.ttl, session.expires_at)
        if expires_at <= issued_at:
            self._deny("snapshot_session_expired", "authentication session has expired")

        claims: dict[str, object] = {
            "iss": self._policy.issuer,
            "aud": self._policy.audience,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": secrets.token_urlsafe(18),
            "token_digest": self._token_digest(auth_token),
            "policy_version": POLICY_VERSION,
            "resource": {
                "type": "space_allocation",
                "id": str(runtime_context.space_id),
            },
            "session": self._session_payload(session),
            "runtime": self._runtime_payload(runtime_context),
        }
        token = self._seal(claims)
        return IssuedContextSnapshot(
            token=token,
            issued_at=issued_at,
            expires_at=expires_at,
            tenant_id=str(runtime_context.tenant_id),
            space_id=str(runtime_context.space_id),
        )

    def verify(self, *, token: str, auth_token: str) -> VerifiedContextSnapshot:
        if not token or not auth_token:
            self._deny("context_snapshot_required", "a bound context snapshot is required")
        claims = self._open(token)
        now = self._now()
        issued_at = self._timestamp(claims.get("iat"), "snapshot_iat_invalid")
        expires_at = self._timestamp(claims.get("exp"), "snapshot_exp_invalid")
        if issued_at > now + timedelta(seconds=5):
            self._deny("snapshot_iat_invalid", "snapshot issue time is in the future")
        if expires_at <= now:
            self._deny("context_snapshot_expired", "context snapshot has expired")
        if expires_at - issued_at > _MAX_SNAPSHOT_TTL:
            self._deny("snapshot_ttl_invalid", "context snapshot exceeds 60 seconds")
        if claims.get("iss") != self._policy.issuer or claims.get("aud") != self._policy.audience:
            self._deny("snapshot_recipient_invalid", "snapshot issuer or audience is invalid")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            self._deny("snapshot_id_invalid", "snapshot identifier is invalid")
        expected_digest = self._token_digest(auth_token)
        actual_digest = claims.get("token_digest")
        if not isinstance(actual_digest, str) or not hmac.compare_digest(
            actual_digest, expected_digest
        ):
            self._deny("snapshot_token_binding_invalid", "snapshot belongs to another session")
        if claims.get("policy_version") != POLICY_VERSION:
            self._deny("snapshot_policy_stale", "snapshot policy version is stale")

        try:
            session_payload = self._mapping(claims["session"])
            runtime_payload = self._mapping(claims["runtime"])
            resource_payload = self._mapping(claims["resource"])
            session = ValidatedAuthSession(
                session_id=self._uuid(session_payload["session_id"]),
                user_id=self._uuid(session_payload["user_id"]),
                security_version=self._positive_int(session_payload["security_version"]),
                authn_method=self._nonempty(session_payload["authn_method"]),
                authenticated_at=self._timestamp(
                    session_payload["authenticated_at"], "snapshot_session_invalid"
                ),
                expires_at=self._timestamp(
                    session_payload["expires_at"], "snapshot_session_invalid"
                ),
            )
            runtime = RuntimeContext(
                actor_id=self._uuid(runtime_payload["actor_id"]),
                tenant_id=self._uuid(runtime_payload["tenant_id"]),
                space_id=self._uuid(runtime_payload["space_id"]),
                project_id=(
                    self._uuid(runtime_payload["project_id"])
                    if runtime_payload.get("project_id") is not None
                    else None
                ),
                user_security_version=self._positive_int(runtime_payload["user_security_version"]),
                tenant_membership_version=self._positive_int(
                    runtime_payload["tenant_membership_version"]
                ),
                space_membership_version=self._positive_int(
                    runtime_payload["space_membership_version"]
                ),
                runtime_partition_id=self._uuid(runtime_payload["runtime_partition_id"]),
                placement_id=self._uuid(runtime_payload["placement_id"]),
                placement_generation=self._positive_int(runtime_payload["placement_generation"]),
                binding_generation=self._positive_int(runtime_payload["binding_generation"]),
                data_region=self._nonempty(runtime_payload["data_region"]),
                physical_workspace_id=self._positive_int(runtime_payload["physical_workspace_id"]),
                runtime_user_key=self._nonempty(runtime_payload["runtime_user_key"]),
                runtime_type=self._nonempty(runtime_payload["runtime_type"]),
                source_revision=self._nonempty(runtime_payload["source_revision"]),
                adapter_contract_version=self._nonempty(
                    runtime_payload["adapter_contract_version"]
                ),
                trace_id=self._nonempty(runtime_payload["trace_id"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ContextSnapshotError(
                "snapshot_claims_invalid", "context snapshot claims are invalid"
            ) from error

        if session.expires_at <= now or session.expires_at < expires_at:
            self._deny("snapshot_session_expired", "snapshot exceeds its authentication session")
        if session.authenticated_at > issued_at + timedelta(seconds=5):
            self._deny("snapshot_session_invalid", "session authentication time is invalid")
        if session.user_id != runtime.actor_id:
            self._deny("snapshot_actor_mismatch", "snapshot session and runtime actors differ")
        if session.security_version != runtime.user_security_version:
            self._deny("snapshot_security_version_stale", "snapshot security facts differ")
        if resource_payload.get("type") != "space_allocation" or resource_payload.get("id") != str(
            runtime.space_id
        ):
            self._deny("snapshot_resource_invalid", "snapshot resource binding is invalid")
        return VerifiedContextSnapshot(
            session=session,
            runtime_context=runtime,
            issued_at=issued_at,
            expires_at=expires_at,
            policy_version=str(claims["policy_version"]),
            snapshot_id=str(claims["jti"]),
        )

    def _seal(self, claims: dict[str, object]) -> str:
        key_id = self._policy.active_key_id
        key = self._policy.keys[key_id]
        header = self._encode_json(
            {"alg": "HS256", "enc": "A256GCM", "kid": key_id, "typ": _HEADER_TYPE}
        )
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        ciphertext = AESGCM(self._encryption_key(key)).encrypt(nonce, plaintext, header.encode())
        payload = self._b64(nonce + ciphertext)
        signature = self._b64(hmac.digest(key, f"{header}.{payload}".encode(), "sha256"))
        return f"{header}.{payload}.{signature}"

    def _open(self, token: str) -> dict[str, Any]:
        if len(token) > 32768:
            self._deny("context_snapshot_invalid", "context snapshot is invalid")
        try:
            header_encoded, payload_encoded, signature_encoded = token.split(".")
            header = json.loads(self._unb64(header_encoded))
            if not isinstance(header, dict):
                raise ValueError
            key_id = header.get("kid")
            if (
                header.get("alg") != "HS256"
                or header.get("enc") != "A256GCM"
                or header.get("typ") != _HEADER_TYPE
                or not isinstance(key_id, str)
                or key_id not in self._policy.keys
            ):
                self._deny("snapshot_header_invalid", "snapshot header is invalid")
            key = self._policy.keys[str(key_id)]
            expected = hmac.digest(key, f"{header_encoded}.{payload_encoded}".encode(), "sha256")
            if not hmac.compare_digest(expected, self._unb64(signature_encoded)):
                self._deny("snapshot_signature_invalid", "snapshot signature is invalid")
            sealed = self._unb64(payload_encoded)
            if len(sealed) < 29:
                raise ValueError
            plaintext = AESGCM(self._encryption_key(key)).decrypt(
                sealed[:12], sealed[12:], header_encoded.encode()
            )
            claims = json.loads(plaintext)
            if not isinstance(claims, dict):
                raise ValueError
            return claims
        except ContextSnapshotError:
            raise
        except Exception as error:
            raise ContextSnapshotError(
                "context_snapshot_invalid", "context snapshot is invalid"
            ) from error

    def _now(self) -> datetime:
        now = self._policy.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("context snapshot clock must return a timezone-aware value")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _session_payload(session: ValidatedAuthSession) -> dict[str, object]:
        return {
            "session_id": str(session.session_id),
            "user_id": str(session.user_id),
            "security_version": session.security_version,
            "authn_method": session.authn_method,
            "authenticated_at": int(session.authenticated_at.timestamp()),
            "expires_at": int(session.expires_at.timestamp()),
        }

    @staticmethod
    def _runtime_payload(runtime: RuntimeContext) -> dict[str, object]:
        return {
            "actor_id": str(runtime.actor_id),
            "tenant_id": str(runtime.tenant_id),
            "space_id": str(runtime.space_id),
            "project_id": str(runtime.project_id) if runtime.project_id is not None else None,
            "user_security_version": runtime.user_security_version,
            "tenant_membership_version": runtime.tenant_membership_version,
            "space_membership_version": runtime.space_membership_version,
            "runtime_partition_id": str(runtime.runtime_partition_id),
            "placement_id": str(runtime.placement_id),
            "placement_generation": runtime.placement_generation,
            "binding_generation": runtime.binding_generation,
            "data_region": runtime.data_region,
            "physical_workspace_id": runtime.physical_workspace_id,
            "runtime_user_key": runtime.runtime_user_key,
            "runtime_type": runtime.runtime_type,
            "source_revision": runtime.source_revision,
            "adapter_contract_version": runtime.adapter_contract_version,
            "trace_id": runtime.trace_id,
        }

    @staticmethod
    def _token_digest(token: str) -> str:
        return sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _encryption_key(key: bytes) -> bytes:
        return sha256(b"omnigent-saas-context-snapshot/aes-gcm\0" + key).digest()

    @staticmethod
    def _encode_json(value: dict[str, object]) -> str:
        return ContextSnapshotService._b64(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _unb64(value: str) -> bytes:
        if not value or "=" in value or len(value) % 4 == 1:
            raise ValueError("base64url value is not canonical")
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
        if ContextSnapshotService._b64(decoded) != value:
            raise ValueError("base64url value is not canonical")
        return decoded

    @staticmethod
    def _mapping(value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise TypeError
        return value

    @staticmethod
    def _timestamp(value: object, code: str) -> datetime:
        if not isinstance(value, int):
            raise ContextSnapshotError(code, "snapshot timestamp is invalid")
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise ContextSnapshotError(code, "snapshot timestamp is invalid") from error

    @staticmethod
    def _uuid(value: object) -> UUID:
        if not isinstance(value, str):
            raise TypeError
        return UUID(value)

    @staticmethod
    def _positive_int(value: object) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError
        return value

    @staticmethod
    def _nonempty(value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError
        return value

    @staticmethod
    def _deny(code: str, message: str) -> Never:
        raise ContextSnapshotError(code, message)
