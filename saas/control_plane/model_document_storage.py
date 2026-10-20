"""Private binary storage for content-blind, canonical model metadata."""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

MAX_MODEL_DOCUMENT_BYTES = 16383
# Format 1, plaintext metadata variant 0, uncompressed encoding 0; never secrets.
_PREFIX = b"OGMD\x01\x00\x00"
_MAX_PAYLOAD_BYTES = MAX_MODEL_DOCUMENT_BYTES - len(_PREFIX)


def _check_limit(value: int) -> None:
    if type(value) is not int or not 0 < value <= _MAX_PAYLOAD_BYTES:
        raise ValueError("invalid model document storage")


def encode_model_document(value: str, *, max_payload_bytes: int = _MAX_PAYLOAD_BYTES) -> bytes:
    _check_limit(max_payload_bytes)
    if not isinstance(value, str) or not 0 < len(value) <= max_payload_bytes:
        raise ValueError("invalid model document storage")
    try:
        payload = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid model document storage") from None
    if len(payload) > max_payload_bytes:
        raise ValueError("invalid model document storage")
    return _PREFIX + payload


def decode_model_document(
    value: bytes | memoryview, *, max_payload_bytes: int = _MAX_PAYLOAD_BYTES
) -> str:
    _check_limit(max_payload_bytes)
    if not isinstance(value, (bytes, memoryview)):
        raise ValueError("invalid model document storage")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if not len(_PREFIX) < size <= len(_PREFIX) + max_payload_bytes:
        raise ValueError("invalid model document storage")
    raw = bytes(value)
    if not raw.startswith(_PREFIX):
        raise ValueError("invalid model document storage")
    try:
        return raw[len(_PREFIX) :].decode("utf-8")
    except UnicodeError:
        raise ValueError("invalid model document storage") from None


def model_document_format(name: str, column: str) -> tuple[sa.CheckConstraint, ...]:
    return (
        sa.CheckConstraint(
            f"substring({column} from 1 for 7) = decode('{_PREFIX.hex()}', 'hex')",
            name=name,
        ).ddl_if(dialect="postgresql"),
        sa.CheckConstraint(
            f"hex(substr({column}, 1, 7)) = '{_PREFIX.hex().upper()}'", name=name
        ).ddl_if(dialect="sqlite"),
    )


class ModelDocumentStorage(TypeDecorator[str]):
    """Keep canonical text and hashes unchanged at the managed store boundary."""

    impl = sa.LargeBinary
    cache_ok = True

    def __init__(self, max_payload_bytes: int = _MAX_PAYLOAD_BYTES) -> None:
        _check_limit(max_payload_bytes)
        self.max_payload_bytes = max_payload_bytes
        super().__init__(length=len(_PREFIX) + max_payload_bytes)

    def process_bind_param(self, value: str | None, dialect: Dialect) -> bytes | None:
        del dialect
        return (
            None
            if value is None
            else encode_model_document(value, max_payload_bytes=self.max_payload_bytes)
        )

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        del dialect
        return (
            None
            if value is None
            else decode_model_document(value, max_payload_bytes=self.max_payload_bytes)
        )
