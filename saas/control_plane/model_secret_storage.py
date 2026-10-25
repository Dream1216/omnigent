"""Private, bounded storage envelope around the existing SecretCipher payload."""

from __future__ import annotations

from typing import Any

from sqlalchemy import LargeBinary
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

MAX_STORED_SECRET_BYTES = 16383
# Version 1, ciphertext variant 1, existing SecretCipher envelope scheme 1.
_PREFIX = b"OGSM\x01\x01\x01"


def encode_model_ciphertext(value: str) -> bytes:
    """Keep KMS/Vault key metadata and row context semantics inside SecretCipher."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_STORED_SECRET_BYTES - len(_PREFIX)
    ):
        raise ValueError("invalid model secret storage")
    try:
        payload = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid model secret storage") from None
    if len(payload) > MAX_STORED_SECRET_BYTES - len(_PREFIX):
        raise ValueError("invalid model secret storage")
    return _PREFIX + payload


def decode_model_ciphertext(value: bytes | memoryview) -> str:
    """Reject plaintext variants and unknown formats instead of guessing a cipher."""
    if not isinstance(value, (bytes, memoryview)):
        raise ValueError("invalid model secret storage")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if not len(_PREFIX) < size <= MAX_STORED_SECRET_BYTES:
        raise ValueError("invalid model secret storage")
    raw = bytes(value)
    if not len(_PREFIX) < len(raw) <= MAX_STORED_SECRET_BYTES or not raw.startswith(_PREFIX):
        raise ValueError("invalid model secret storage")
    try:
        return raw[len(_PREFIX) :].decode("utf-8")
    except UnicodeError:
        raise ValueError("invalid model secret storage") from None


class ModelCiphertextStorage(TypeDecorator[str]):
    """Expose only the original opaque ciphertext string to the credential service."""

    impl = LargeBinary(MAX_STORED_SECRET_BYTES)
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> bytes | None:
        del dialect
        return None if value is None else encode_model_ciphertext(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        del dialect
        return None if value is None else decode_model_ciphertext(value)
