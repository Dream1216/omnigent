"""Conservative OpenAPI compatibility checks for the isolated public API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

JsonObject = dict[str, object]
SchemaDirection = Literal["request", "response"]
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


@dataclass(frozen=True, order=True, slots=True)
class BreakingChange:
    location: str
    reason: str

    def render(self) -> str:
        return f"{self.location}: {self.reason}"


def _object(value: object) -> JsonObject:
    return cast(JsonObject, value) if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return (
        list(value) if isinstance(value, Sequence) and not isinstance(value, str | bytes) else []
    )


def _resolve(document: JsonObject, schema: JsonObject) -> JsonObject:
    reference = schema.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/components/schemas/"):
        return schema
    name = reference.removeprefix("#/components/schemas/")
    return _object(_object(_object(document.get("components")).get("schemas")).get(name))


def _parameter_map(operation: JsonObject) -> dict[tuple[str, str], JsonObject]:
    result: dict[tuple[str, str], JsonObject] = {}
    for value in _sequence(operation.get("parameters")):
        parameter = _object(value)
        name = parameter.get("name")
        location = parameter.get("in")
        if isinstance(name, str) and isinstance(location, str):
            result[(location, name)] = parameter
    return result


def _check_numeric_constraint(
    *,
    old: JsonObject,
    new: JsonObject,
    keyword: str,
    direction: SchemaDirection,
    location: str,
    changes: list[BreakingChange],
) -> None:
    old_value = old.get(keyword)
    new_value = new.get(keyword)
    if not isinstance(old_value, int | float) or not isinstance(new_value, int | float):
        return
    tighter = new_value > old_value if keyword.startswith("min") else new_value < old_value
    if direction == "request" and tighter:
        changes.append(BreakingChange(location, f"{keyword} became more restrictive"))
    if direction == "response" and not tighter and new_value != old_value:
        changes.append(BreakingChange(location, f"{keyword} allows new response values"))


def _check_schema(
    *,
    old_document: JsonObject,
    new_document: JsonObject,
    old_schema: JsonObject,
    new_schema: JsonObject,
    direction: SchemaDirection,
    location: str,
    changes: list[BreakingChange],
    visited: set[tuple[int, int, SchemaDirection]],
) -> None:
    old_resolved = _resolve(old_document, old_schema)
    new_resolved = _resolve(new_document, new_schema)
    visit = (id(old_resolved), id(new_resolved), direction)
    if visit in visited:
        return
    visited.add(visit)

    old_type = old_resolved.get("type")
    new_type = new_resolved.get("type")
    if old_type is not None and old_type != new_type:
        changes.append(
            BreakingChange(location, f"schema type changed from {old_type} to {new_type}")
        )
        return

    old_enum = set(_sequence(old_resolved.get("enum")))
    new_enum = set(_sequence(new_resolved.get("enum")))
    if old_enum and new_enum:
        removed = old_enum - new_enum
        added = new_enum - old_enum
        if direction == "request" and removed:
            changes.append(
                BreakingChange(
                    location,
                    f"request enum values removed: {sorted(map(repr, removed))!r}",
                )
            )
        if direction == "response" and added:
            changes.append(
                BreakingChange(
                    location,
                    f"response enum values added: {sorted(map(repr, added))!r}",
                )
            )

    if (
        old_resolved.get("pattern") != new_resolved.get("pattern")
        and old_resolved.get("pattern") is not None
    ):
        changes.append(BreakingChange(location, "schema pattern changed"))

    for keyword in ("minimum", "exclusiveMinimum", "minLength", "minItems"):
        _check_numeric_constraint(
            old=old_resolved,
            new=new_resolved,
            keyword=keyword,
            direction=direction,
            location=location,
            changes=changes,
        )
    for keyword in ("maximum", "exclusiveMaximum", "maxLength", "maxItems"):
        _check_numeric_constraint(
            old=old_resolved,
            new=new_resolved,
            keyword=keyword,
            direction=direction,
            location=location,
            changes=changes,
        )

    old_required = {str(value) for value in _sequence(old_resolved.get("required"))}
    new_required = {str(value) for value in _sequence(new_resolved.get("required"))}
    if direction == "request":
        newly_required = new_required - old_required
        if newly_required:
            changes.append(
                BreakingChange(
                    location, f"request properties became required: {sorted(newly_required)!r}"
                )
            )
    else:
        no_longer_required = old_required - new_required
        if no_longer_required:
            changes.append(
                BreakingChange(
                    location,
                    "response properties are no longer guaranteed: "
                    f"{sorted(no_longer_required)!r}",
                )
            )

    old_properties = _object(old_resolved.get("properties"))
    new_properties = _object(new_resolved.get("properties"))
    if direction == "response" and old_resolved.get("additionalProperties") is False:
        added_properties = set(new_properties) - set(old_properties)
        if added_properties:
            changes.append(
                BreakingChange(
                    location,
                    "strict response properties were added: "
                    f"{sorted(added_properties)!r}",
                )
            )
        if new_resolved.get("additionalProperties") is not False:
            changes.append(
                BreakingChange(location, "strict response now permits additional properties")
            )
    for name, old_property in old_properties.items():
        if name not in new_properties:
            changes.append(BreakingChange(f"{location}.{name}", "schema property was removed"))
            continue
        _check_schema(
            old_document=old_document,
            new_document=new_document,
            old_schema=_object(old_property),
            new_schema=_object(new_properties[name]),
            direction=direction,
            location=f"{location}.{name}",
            changes=changes,
            visited=visited,
        )

    old_items = _object(old_resolved.get("items"))
    new_items = _object(new_resolved.get("items"))
    if old_items:
        if not new_items:
            changes.append(BreakingChange(location, "array item schema was removed"))
        else:
            _check_schema(
                old_document=old_document,
                new_document=new_document,
                old_schema=old_items,
                new_schema=new_items,
                direction=direction,
                location=f"{location}[]",
                changes=changes,
                visited=visited,
            )


def _check_operation(
    *,
    old_document: JsonObject,
    new_document: JsonObject,
    old_operation: JsonObject,
    new_operation: JsonObject,
    location: str,
    changes: list[BreakingChange],
) -> None:
    if old_operation.get("operationId") != new_operation.get("operationId"):
        changes.append(BreakingChange(location, "operationId changed"))
    for extension in (
        "x-omnigent-required-permission",
        "x-omnigent-cursor-binding",
    ):
        if old_operation.get(extension) != new_operation.get(extension):
            changes.append(BreakingChange(location, f"{extension} changed"))

    old_security = old_operation.get("security", old_document.get("security"))
    new_security = new_operation.get("security", new_document.get("security"))
    if old_security != new_security:
        changes.append(BreakingChange(location, "security requirements changed"))

    old_parameters = _parameter_map(old_operation)
    new_parameters = _parameter_map(new_operation)
    for key, old_parameter in old_parameters.items():
        parameter_location = f"{location} parameter {key[0]}:{key[1]}"
        if key not in new_parameters:
            changes.append(BreakingChange(parameter_location, "parameter was removed"))
            continue
        new_parameter = new_parameters[key]
        if not old_parameter.get("required", False) and new_parameter.get("required", False):
            changes.append(BreakingChange(parameter_location, "parameter became required"))
        _check_schema(
            old_document=old_document,
            new_document=new_document,
            old_schema=_object(old_parameter.get("schema")),
            new_schema=_object(new_parameter.get("schema")),
            direction="request",
            location=parameter_location,
            changes=changes,
            visited=set(),
        )
    for key, new_parameter in new_parameters.items():
        if key not in old_parameters and new_parameter.get("required", False):
            changes.append(
                BreakingChange(
                    f"{location} parameter {key[0]}:{key[1]}",
                    "new required parameter was added",
                )
            )

    old_request = _object(old_operation.get("requestBody"))
    new_request = _object(new_operation.get("requestBody"))
    if old_request:
        if not new_request:
            changes.append(BreakingChange(location, "request body was removed"))
        else:
            if not old_request.get("required", False) and new_request.get("required", False):
                changes.append(BreakingChange(location, "request body became required"))
            _check_content(
                old_document=old_document,
                new_document=new_document,
                old_content=_object(old_request.get("content")),
                new_content=_object(new_request.get("content")),
                direction="request",
                location=f"{location} request",
                changes=changes,
            )
    elif new_request.get("required", False):
        changes.append(BreakingChange(location, "new required request body was added"))

    old_responses = _object(old_operation.get("responses"))
    new_responses = _object(new_operation.get("responses"))
    for status, old_response_value in old_responses.items():
        response_location = f"{location} response {status}"
        if status not in new_responses:
            changes.append(BreakingChange(response_location, "response status was removed"))
            continue
        old_response = _object(old_response_value)
        new_response = _object(new_responses[status])
        old_headers = _object(old_response.get("headers"))
        new_headers = _object(new_response.get("headers"))
        for header in old_headers:
            if header not in new_headers:
                changes.append(
                    BreakingChange(
                        f"{response_location} header {header}", "response header removed"
                    )
                )
        _check_content(
            old_document=old_document,
            new_document=new_document,
            old_content=_object(old_response.get("content")),
            new_content=_object(new_response.get("content")),
            direction="response",
            location=response_location,
            changes=changes,
        )


def _check_content(
    *,
    old_document: JsonObject,
    new_document: JsonObject,
    old_content: JsonObject,
    new_content: JsonObject,
    direction: SchemaDirection,
    location: str,
    changes: list[BreakingChange],
) -> None:
    for media_type, old_media in old_content.items():
        media_location = f"{location} {media_type}"
        if media_type not in new_content:
            changes.append(BreakingChange(media_location, "media type was removed"))
            continue
        _check_schema(
            old_document=old_document,
            new_document=new_document,
            old_schema=_object(_object(old_media).get("schema")),
            new_schema=_object(_object(new_content[media_type]).get("schema")),
            direction=direction,
            location=media_location,
            changes=changes,
            visited=set(),
        )


def find_breaking_changes(
    old_document: Mapping[str, object], new_document: Mapping[str, object]
) -> tuple[BreakingChange, ...]:
    """Compare old to new and return deterministic consumer-visible breaks."""

    old = dict(old_document)
    new = dict(new_document)
    changes: list[BreakingChange] = []
    for extension in (
        "x-omnigent-api-version",
        "x-omnigent-stability",
        "x-omnigent-deprecation-policy",
    ):
        if old.get(extension) != new.get(extension):
            changes.append(BreakingChange("document", f"{extension} changed"))
    old_paths = _object(old.get("paths"))
    new_paths = _object(new.get("paths"))
    for path, old_path_value in old_paths.items():
        if path not in new_paths:
            changes.append(BreakingChange(path, "path was removed"))
            continue
        old_path = _object(old_path_value)
        new_path = _object(new_paths[path])
        for method, old_operation_value in old_path.items():
            if method not in _HTTP_METHODS:
                continue
            location = f"{method.upper()} {path}"
            if method not in new_path:
                changes.append(BreakingChange(location, "operation was removed"))
                continue
            _check_operation(
                old_document=old,
                new_document=new,
                old_operation=_object(old_operation_value),
                new_operation=_object(new_path[method]),
                location=location,
                changes=changes,
            )
    return tuple(sorted(set(changes)))


__all__ = ["BreakingChange", "find_breaking_changes"]
