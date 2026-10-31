"""Replica-shared OIDC transaction keys with explicit, authenticated key IDs."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from saas.control_plane.lifecycle import LifecycleError

_KEY_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@dataclass(frozen=True, slots=True)
class OidcTransactionKeyring:
    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if not 1 <= len(self.keys) <= 8 or self.active_key_id not in self.keys:
            raise ValueError("OIDC transaction keyring is invalid")
        if any(
            not isinstance(key_id, str)
            or not _KEY_ID.fullmatch(key_id)
            or not isinstance(key, bytes)
            or len(key) != 32
            for key_id, key in self.keys.items()
        ):
            raise ValueError("OIDC transaction keys require valid IDs and exactly 32 bytes")
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

    @staticmethod
    def key_id(encoded: str) -> str:
        return encoded.split(".", 1)[0] if "." in encoded else "legacy"

    def encrypt(self, plaintext: bytes, *, state_hash: str, nonce: bytes) -> str:
        key_id = self.active_key_id
        associated = state_hash if key_id == "legacy" else f"{key_id}\0{state_hash}"
        ciphertext = AESGCM(self.keys[key_id]).encrypt(
            nonce, plaintext, associated.encode("ascii")
        )
        encoded = base64.urlsafe_b64encode(nonce + ciphertext).rstrip(b"=").decode("ascii")
        return encoded if key_id == "legacy" else f"{key_id}.{encoded}"

    def decrypt(self, encoded: str, *, state_hash: str) -> bytes:
        key_id = self.key_id(encoded)
        value = encoded.split(".", 1)[1] if "." in encoded else encoded
        try:
            key = self.keys[key_id]
            payload = base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
            )
            if len(payload) < 29:
                raise ValueError
            associated = state_hash if key_id == "legacy" else f"{key_id}\0{state_hash}"
            return AESGCM(key).decrypt(payload[:12], payload[12:], associated.encode("ascii"))
        except (KeyError, InvalidTag, ValueError, UnicodeError) as error:
            raise LifecycleError(
                "oidc_transaction_invalid", "OIDC transaction verifier is invalid"
            ) from error
