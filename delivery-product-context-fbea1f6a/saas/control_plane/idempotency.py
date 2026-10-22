"""Opaque, scope-bound database keys for public idempotency tokens."""

from __future__ import annotations

from hashlib import sha256
from uuid import UUID


def scoped_idempotency_key(scope: str, scope_id: UUID | str, key: str) -> str:
    """Prevent one security scope's caller-selected key from colliding with another."""

    encoded = f"{scope}\x00{scope_id}\x00{key}".encode()
    return sha256(encoded).hexdigest()
