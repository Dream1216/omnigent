"""Bounded model-management pages share the Staff cursor response contract."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar
from uuid import UUID

from saas.control_plane.platform_security import PlatformSecurityError

_T = TypeVar("_T")


@dataclass(frozen=True)
class ModelPage(Generic[_T]):
    items: tuple[_T, ...]
    next_cursor: str | None


def invalid_model_page() -> PlatformSecurityError:
    return PlatformSecurityError("platform_page_invalid", "Model page is invalid")


def validate_model_page(limit: int, cursor: UUID | None) -> None:
    if (
        type(limit) is not int
        or not 1 <= limit <= 100
        or (cursor is not None and (not isinstance(cursor, UUID) or cursor.int == 0))
    ):
        raise invalid_model_page()


def model_page_cursor(keys: Sequence[UUID], limit: int) -> str | None:
    return str(keys[limit - 1]) if len(keys) > limit else None
