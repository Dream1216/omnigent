"""The worker's authenticated read capability, independent of Casdoor admin keys."""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from saas.control_plane.identity_events import IdentitySyncError, ProviderIdentityState
from saas.control_plane.identity_private_channel import (
    PrivateIdentityKeys,
    verified_identity_tls_context,
)
from saas.control_plane.identity_read_protocol import (
    IDENTITY_READ_KEY_ID,
    IDENTITY_READ_MAX_BYTES,
    IDENTITY_READ_PATH,
    IDENTITY_READ_SECRET,
    decode_identity_read,
)
from saas.production.identity_read_broker import IdentityReadBrokerPins


@dataclass(frozen=True, slots=True)
class IdentityReadClientConfig:
    origin: str
    key_id: str
    secret: str = field(repr=False)
    pins: IdentityReadBrokerPins
    tls_context: ssl.SSLContext | bool = field(default=True, repr=False)
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        url = urlsplit(self.origin)
        port = url.port
        PrivateIdentityKeys({self.key_id: self.secret})
        if (
            not url.hostname
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
            or self.origin != f"{url.scheme}://{url.netloc}"
            or (port is not None and not 1 <= port <= 65535)
            or (
                url.scheme != "https"
                and not (
                    self.pins.allow_insecure_loopback
                    and url.scheme == "http"
                    and url.hostname in {"localhost", "127.0.0.1", "::1"}
                )
            )
            or self.tls_context is False
            or (
                type(self.tls_context) is not bool
                and not isinstance(self.tls_context, ssl.SSLContext)
            )
            or type(self.timeout_seconds) not in {int, float}
            or not 1 <= self.timeout_seconds <= 20
        ):
            raise ValueError("identity read client configuration is invalid")
        verified_identity_tls_context(self.tls_context)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.key_id) is None:
            raise ValueError("identity read client key identifier is invalid")


class IdentityReadClient:
    def __init__(
        self, config: IdentityReadClientConfig, *, transport: httpx.BaseTransport | None = None
    ):
        self._config, self._transport = config, transport

    def read_identity(self, subject: str) -> ProviderIdentityState:
        if (
            not isinstance(subject, str)
            or not 1 <= len(subject) <= 512
            or any(ord(c) < 32 for c in subject)
        ):
            raise IdentitySyncError("identity_provider_subject_invalid")
        config = self._config
        try:
            with (
                httpx.Client(
                    base_url=config.origin,
                    transport=self._transport,
                    verify=config.tls_context,
                    timeout=httpx.Timeout(config.timeout_seconds),
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    "GET",
                    IDENTITY_READ_PATH,
                    params={"subject": subject},
                    headers={
                        IDENTITY_READ_KEY_ID: config.key_id,
                        IDENTITY_READ_SECRET: config.secret,
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                ) as response,
            ):
                if response.status_code in {401, 403}:
                    raise IdentitySyncError("identity_reader_authentication_failed")
                if response.status_code != 200:
                    raise IdentitySyncError("identity_reader_unavailable", retryable=True)
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "application/json"
                    or response.headers.get("content-encoding", "identity") != "identity"
                ):
                    raise IdentitySyncError("identity_reader_response_invalid", retryable=True)
                body = bytearray()
                for chunk in response.iter_bytes(chunk_size=4096):
                    body.extend(chunk)
                    if len(body) > IDENTITY_READ_MAX_BYTES:
                        raise IdentitySyncError("identity_reader_response_invalid", retryable=True)
            pins = config.pins
            return decode_identity_read(
                bytes(body),
                issuer=pins.issuer,
                organization=pins.organization,
                subject=subject,
                broker_revision=pins.broker_revision,
                provider_source_lock_sha256=pins.provider_source_lock_sha256,
                now=datetime.now(timezone.utc),
            )
        except httpx.HTTPError:
            raise IdentitySyncError("identity_reader_unavailable", retryable=True) from None
