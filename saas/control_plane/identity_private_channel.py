"""Bounded rotating authentication keys for independent private identity channels."""

from __future__ import annotations

import hmac
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from starlette.requests import Request


@dataclass(frozen=True, slots=True)
class PrivateIdentityKeys:
    keys: Mapping[str, str] = field(repr=False)
    allow_insecure_loopback: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.allow_insecure_loopback) is not bool
            or not 1 <= len(self.keys) <= 8
            or any(
                not isinstance(key_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id)
                or not isinstance(secret, str)
                or not 32 <= len(secret) <= 256
                or not secret.isascii()
                or any(ord(char) < 33 or ord(char) > 126 for char in secret)
                for key_id, secret in self.keys.items()
            )
        ):
            raise ValueError("private identity channel keys are invalid")
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    def accepts(self, key_id: str, secret: str) -> bool:
        expected = self.keys.get(key_id)
        candidate = expected or "x" * 43
        if len(secret) > 256 or not secret.isascii():
            return False
        matched = hmac.compare_digest(secret, candidate)
        return expected is not None and matched


def private_identity_https(request: Request, *, allow_insecure_loopback: bool) -> bool:
    loopback = (
        request.client is not None
        and request.client.host in {"127.0.0.1", "::1"}
        and request.url.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    return request.url.scheme == "https" or (allow_insecure_loopback and loopback)


def verified_identity_tls_context(value: ssl.SSLContext | bool) -> ssl.SSLContext | bool:
    if value is True:
        return value
    if (
        not isinstance(value, ssl.SSLContext)
        or not value.check_hostname
        or value.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("identity channel TLS verification is required")
    return value
