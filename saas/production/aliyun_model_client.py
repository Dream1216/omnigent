"""Cloud Host credential client; model signing and provider keys stay on the server."""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from collections.abc import Callable
from urllib.parse import urlsplit
from uuid import UUID

import httpx

ALIYUN_MODEL_TOKEN_TTL_SECONDS = 300
_MAX_RESPONSE_BYTES = 16384


class AliyunModelCredentialError(PermissionError):
    """Remote model admission failed without exposing its credential or response."""


def validated_server_origin(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Aliyun Host server TLS origin is invalid")
    try:
        url = urlsplit(value)
        valid = (
            isinstance(value, str)
            and value == value.strip()
            and url.scheme == "https"
            and bool(url.hostname)
            and url.username is None
            and url.password is None
            and url.port in (None, 443)
            and url.path in ("", "/")
            and not url.query
            and not url.fragment
            and not any(ord(c) < 33 or ord(c) > 126 for c in value)
            and "%" not in value
            and "\\" not in value
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("Aliyun Host server TLS origin is invalid")
    return value.removesuffix("/")


class AliyunHostModelTokenIssuer:
    def __init__(
        self,
        *,
        server_url: str,
        host_id: str,
        workspace_id: int,
        tenant_id: UUID,
        host_token: str,
        lease: str,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        self._origin = validated_server_origin(server_url)
        if (
            re.fullmatch(r"[A-Za-z0-9_-]{1,128}", host_id) is None
            or type(workspace_id) is not int
            or not 0 < workspace_id < 2**63
            or not isinstance(tenant_id, UUID)
            or tenant_id.int == 0
            or re.fullmatch(r"[A-Za-z0-9_-]{32,512}", host_token) is None
            or re.fullmatch(r"[A-Za-z0-9_-]{1,16300}\.[A-Za-z0-9_-]{43}", lease) is None
        ):
            raise ValueError("Aliyun Host model identity is invalid")
        self._host_id = host_id
        self._workspace_id = workspace_id
        self._tenant_id = tenant_id
        self._host_token = host_token
        self._lease = lease
        self._client_factory = client_factory or (
            lambda: httpx.Client(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=False,
                trust_env=False,
            )
        )

    def issue(
        self,
        *,
        session_id: UUID,
        ttl_seconds: int = ALIYUN_MODEL_TOKEN_TTL_SECONDS,
        now: int | None = None,
    ) -> str:
        if (
            not isinstance(session_id, UUID)
            or session_id.int == 0
            or type(ttl_seconds) is not int
            or ttl_seconds != ALIYUN_MODEL_TOKEN_TTL_SECONDS
        ):
            raise AliyunModelCredentialError("Aliyun model credential request is invalid")
        try:
            with (
                self._client_factory() as client,
                client.stream(
                    "POST",
                    f"{self._origin}/v1/hosts/{self._host_id}/sessions/{session_id.hex}/model-token",
                    headers={
                        "X-Omnigent-Host-Token": self._host_token,
                        "X-Omnigent-Model-Lease": self._lease,
                        "X-Omnigent-Workspace-Id": str(self._workspace_id),
                        "Accept": "application/json",
                    },
                    follow_redirects=False,
                ) as response,
            ):
                if response.status_code != 200:
                    raise ValueError("model admission denied")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise ValueError("model credential response is oversized")
            return self._validated_token(json.loads(body), session_id, now=now)
        except (httpx.HTTPError, ValueError, TypeError, KeyError, UnicodeError, binascii.Error):
            raise AliyunModelCredentialError("Aliyun model credential is unavailable") from None

    def _validated_token(self, document: object, session_id: UUID, *, now: int | None) -> str:
        current = int(time.time()) if now is None else now
        if not isinstance(document, dict) or set(document) != {"token", "expires_at"}:
            raise ValueError("invalid model credential response")
        token = document["token"]
        if (
            not isinstance(token, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{43}", token) is None
        ):
            raise ValueError("invalid model credential")
        segment = token.split(".")[0]
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        claims = json.loads(raw)
        # TLS authenticates the issuer; these checks bind its response to this request.
        if (
            not isinstance(claims, dict)
            or set(claims) != {"aud", "exp", "iat", "iss", "sid", "tid", "v"}
            or json.dumps(claims, sort_keys=True, separators=(",", ":")).encode() != raw
            or type(claims["v"]) is not int
            or claims["v"] != 1
            or claims["aud"] != "omnigent-platform-model-gateway"
            or claims["iss"] != "omnigent-platform-model-host"
            or claims["tid"] != str(self._tenant_id)
            or claims["sid"] != str(session_id)
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or type(document["expires_at"]) is not int
            or document["expires_at"] != claims["exp"]
            or type(current) is not int
            or claims["iat"] > current + 30
            or not 0 < claims["exp"] - claims["iat"] <= ALIYUN_MODEL_TOKEN_TTL_SECONDS
            or claims["exp"] <= current
        ):
            raise ValueError("invalid model credential binding")
        return token
