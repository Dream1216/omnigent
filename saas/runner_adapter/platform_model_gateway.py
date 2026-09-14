"""Session-bound credentials for the Platform-managed model gateway."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import time
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from saas.runner_adapter.platform_models import PLATFORM_MODEL_CREDENTIAL_ENV

_TOKEN_VERSION = 1
_MAX_TOKEN_TTL_SECONDS = 8 * 60 * 60


class PlatformModelGatewayTokenError(ValueError):
    """A model-gateway bearer is malformed, expired, or outside its partition."""


@dataclass(frozen=True, slots=True)
class PlatformModelGatewayClaims:
    tenant_id: UUID
    session_id: UUID
    issued_at: int
    expires_at: int


class PlatformModelGatewayTokenAuthority:
    """Issue and validate HMAC bearers bound to one Runtime Partition tenant."""

    def __init__(
        self,
        *,
        signing_key: bytes,
        tenant_id: UUID,
        issuer: str = "omnigent-platform-model-host",
        audience: str = "omnigent-platform-model-gateway",
    ) -> None:
        if len(signing_key) < 32 or tenant_id.int == 0 or not issuer or not audience:
            raise ValueError("Platform model gateway token authority is invalid")
        self._key = signing_key
        self.tenant_id = tenant_id
        self.issuer = issuer
        self.audience = audience

    def issue(
        self,
        *,
        session_id: UUID,
        ttl_seconds: int = 60 * 60,
        now: int | None = None,
    ) -> str:
        if (
            session_id.int == 0
            or isinstance(ttl_seconds, bool)
            or not 1 <= ttl_seconds <= _MAX_TOKEN_TTL_SECONDS
        ):
            raise ValueError("Platform model gateway token request is invalid")
        issued_at = int(time.time()) if now is None else now
        payload = {
            "aud": self.audience,
            "exp": issued_at + ttl_seconds,
            "iat": issued_at,
            "iss": self.issuer,
            "sid": str(session_id),
            "tid": str(self.tenant_id),
            "v": _TOKEN_VERSION,
        }
        encoded = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self._key, encoded.encode("ascii"), sha256).digest())
        return f"{encoded}.{signature}"

    def validate(self, token: str, *, now: int | None = None) -> PlatformModelGatewayClaims:
        try:
            encoded, signature = token.split(".")
            expected = _b64(hmac.new(self._key, encoded.encode("ascii"), sha256).digest())
            if not hmac.compare_digest(signature, expected):
                raise PlatformModelGatewayTokenError("invalid signature")
            document = json.loads(_unb64(encoded))
            if not isinstance(document, dict) or set(document) != {
                "aud",
                "exp",
                "iat",
                "iss",
                "sid",
                "tid",
                "v",
            }:
                raise PlatformModelGatewayTokenError("invalid claims")
            issued_at = document["iat"]
            expires_at = document["exp"]
            current = int(time.time()) if now is None else now
            tenant_id = UUID(document["tid"])
            session_id = UUID(document["sid"])
            if (
                document["v"] != _TOKEN_VERSION
                or document["iss"] != self.issuer
                or document["aud"] != self.audience
                or tenant_id != self.tenant_id
                or tenant_id.int == 0
                or session_id.int == 0
                or isinstance(issued_at, bool)
                or isinstance(expires_at, bool)
                or not isinstance(issued_at, int)
                or not isinstance(expires_at, int)
                or issued_at > current + 30
                or expires_at <= current
                or expires_at - issued_at > _MAX_TOKEN_TTL_SECONDS
            ):
                raise PlatformModelGatewayTokenError("invalid claims")
        except PlatformModelGatewayTokenError:
            raise
        except (ValueError, TypeError, UnicodeError, binascii.Error):
            raise PlatformModelGatewayTokenError("invalid token") from None
        return PlatformModelGatewayClaims(
            tenant_id=tenant_id,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def inject_platform_model_gateway_token(
    environment: dict[str, str],
    *,
    authority: PlatformModelGatewayTokenAuthority,
    session_id: UUID,
    ttl_seconds: int = 60 * 60,
) -> None:
    """Put one synthetic, session-bound bearer into the Runner-only environment."""

    if environment.get(PLATFORM_MODEL_CREDENTIAL_ENV):
        raise ValueError("Platform model gateway credential is already present")
    environment[PLATFORM_MODEL_CREDENTIAL_ENV] = authority.issue(
        session_id=session_id,
        ttl_seconds=ttl_seconds,
    )


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


__all__ = [
    "PlatformModelGatewayClaims",
    "PlatformModelGatewayTokenAuthority",
    "PlatformModelGatewayTokenError",
    "inject_platform_model_gateway_token",
]
