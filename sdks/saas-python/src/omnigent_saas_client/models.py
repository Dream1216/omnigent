"""Dependency-light public API request and response models."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, TypeAlias, TypeVar, cast

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
T = TypeVar("T")


def _mapping(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _integer(value: object, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _optional_string(value: object, field_name: str) -> str | None:
    return None if value is None else _string(value, field_name)


def _datetime(value: object, field_name: str) -> datetime:
    text = _string(value, field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed


def _optional_datetime(value: object, field_name: str) -> datetime | None:
    return None if value is None else _datetime(value, field_name)


@dataclass(frozen=True, slots=True)
class Page(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    space_id: str
    name: str
    visibility: str
    status: str
    authorization_version: int
    created_at: datetime
    updated_at: datetime
    etag: str

    @classmethod
    def from_dict(cls, value: object) -> Project:
        item = _mapping(value, "project")
        return cls(
            id=_string(item.get("id"), "project.id"),
            space_id=_string(item.get("space_id"), "project.space_id"),
            name=_string(item.get("name"), "project.name"),
            visibility=_string(item.get("visibility"), "project.visibility"),
            status=_string(item.get("status"), "project.status"),
            authorization_version=_integer(
                item.get("authorization_version"), "project.authorization_version"
            ),
            created_at=_datetime(item.get("created_at"), "project.created_at"),
            updated_at=_datetime(item.get("updated_at"), "project.updated_at"),
            etag=_string(item.get("etag"), "project.etag"),
        )


@dataclass(frozen=True, slots=True)
class Run:
    id: str
    project_id: str
    task_id: str
    session_id: str | None
    parent_run_id: str | None
    status: str
    version: int
    event_sequence: int
    queue_class: str
    priority: int
    metadata: dict[str, JsonValue]
    created_at: datetime
    updated_at: datetime
    terminal_at: datetime | None
    etag: str

    @classmethod
    def from_dict(cls, value: object) -> Run:
        item = _mapping(value, "run")
        return cls(
            id=_string(item.get("id"), "run.id"),
            project_id=_string(item.get("project_id"), "run.project_id"),
            task_id=_string(item.get("task_id"), "run.task_id"),
            session_id=_optional_string(item.get("session_id"), "run.session_id"),
            parent_run_id=_optional_string(item.get("parent_run_id"), "run.parent_run_id"),
            status=_string(item.get("status"), "run.status"),
            version=_integer(item.get("version"), "run.version"),
            event_sequence=_integer(item.get("event_sequence"), "run.event_sequence"),
            queue_class=_string(item.get("queue_class"), "run.queue_class"),
            priority=_integer(item.get("priority"), "run.priority"),
            metadata=cast(dict[str, JsonValue], _mapping(item.get("metadata"), "run.metadata")),
            created_at=_datetime(item.get("created_at"), "run.created_at"),
            updated_at=_datetime(item.get("updated_at"), "run.updated_at"),
            terminal_at=_optional_datetime(item.get("terminal_at"), "run.terminal_at"),
            etag=_string(item.get("etag"), "run.etag"),
        )


@dataclass(frozen=True, slots=True)
class RunContent:
    run_id: str
    input: dict[str, JsonValue]
    product_revision: str
    upstream_revision: str
    schema_revision: str
    adapter_contract_version: str
    etag: str

    @classmethod
    def from_dict(cls, value: object) -> RunContent:
        item = _mapping(value, "run_content")
        return cls(
            run_id=_string(item.get("run_id"), "run_content.run_id"),
            input=cast(
                dict[str, JsonValue],
                _mapping(item.get("input"), "run_content.input"),
            ),
            product_revision=_string(item.get("product_revision"), "run_content.product_revision"),
            upstream_revision=_string(
                item.get("upstream_revision"), "run_content.upstream_revision"
            ),
            schema_revision=_string(item.get("schema_revision"), "run_content.schema_revision"),
            adapter_contract_version=_string(
                item.get("adapter_contract_version"),
                "run_content.adapter_contract_version",
            ),
            etag=_string(item.get("etag"), "run_content.etag"),
        )


@dataclass(frozen=True, slots=True)
class RunEvent:
    id: str
    run_id: str
    sequence: int
    type: str
    data: dict[str, JsonValue]
    trace_id: str
    created_at: datetime

    @classmethod
    def from_dict(cls, value: object) -> RunEvent:
        item = _mapping(value, "event")
        return cls(
            id=_string(item.get("id"), "event.id"),
            run_id=_string(item.get("run_id"), "event.run_id"),
            sequence=_integer(item.get("sequence"), "event.sequence"),
            type=_string(item.get("type"), "event.type"),
            data=cast(dict[str, JsonValue], _mapping(item.get("data"), "event.data")),
            trace_id=_string(item.get("trace_id"), "event.trace_id"),
            created_at=_datetime(item.get("created_at"), "event.created_at"),
        )


@dataclass(frozen=True, slots=True)
class RunCreate:
    title: str
    input: dict[str, JsonValue]
    session_id: str | None = None
    queue_class: str = "interactive"
    priority: int = 0
    quota_resource: str = "run"
    quota_units: int = 1
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "input": self.input,
            "session_id": self.session_id,
            "queue_class": self.queue_class,
            "priority": self.priority,
            "quota_resource": self.quota_resource,
            "quota_units": self.quota_units,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class RunRetry:
    input_override: dict[str, JsonValue] | None = None
    queue_class: str | None = None
    priority: int | None = None
    metadata: dict[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "input_override": self.input_override,
            "queue_class": self.queue_class,
            "priority": self.priority,
            "metadata": self.metadata,
        }


def page_from_dict(value: object, parser: Callable[[object], T]) -> Page[T]:
    payload = _mapping(value, "page")
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("page.items must be an array")
    return Page(
        items=tuple(parser(item) for item in raw_items),
        next_cursor=_optional_string(payload.get("next_cursor"), "page.next_cursor"),
    )


__all__ = [
    "JsonValue",
    "Page",
    "Project",
    "Run",
    "RunContent",
    "RunCreate",
    "RunEvent",
    "RunRetry",
    "page_from_dict",
]
