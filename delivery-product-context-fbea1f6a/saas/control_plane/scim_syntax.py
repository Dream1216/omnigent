"""Bounded RFC 7644 filter and PATCH path syntax."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import NoReturn, cast

_CORE_SCHEMAS = {
    "user": "urn:ietf:params:scim:schemas:core:2.0:User",
    "group": "urn:ietf:params:scim:schemas:core:2.0:Group",
}
_EXTENSION_SCHEMAS = {
    "enterprise_user": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
}
_SUPPORTED_SCHEMAS = (*_CORE_SCHEMAS.values(), *_EXTENSION_SCHEMAS.values())
_ATTRIBUTE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*|\$ref")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


class ScimSyntaxError(ValueError):
    def __init__(self, scim_type: str, message: str) -> None:
        self.scim_type = scim_type
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ScimFilterExpression:
    operator: str
    attribute: str | None = None
    value: str | bool | int | float | None = None
    operands: tuple[ScimFilterExpression, ...] = ()
    schema: str | None = None
    sub_attribute: str | None = None


@dataclass(frozen=True, slots=True)
class ScimPatchPath:
    attribute: str
    schema: str | None = None
    value_filter: ScimFilterExpression | None = None
    sub_attribute: str | None = None


class _ScimExpressionParser:
    def __init__(self, value: str, *, error_type: str) -> None:
        self._error_type = error_type
        self._tokens = self._tokenize(value)
        self._index = 0
        self._depth = 0

    def parse_filter(self) -> ScimFilterExpression:
        if not self._tokens:
            self._invalid()
        expression = self._parse_or(allow_value_path=True)
        if self._index != len(self._tokens):
            self._invalid()
        return expression

    def parse_patch_path(self) -> ScimPatchPath:
        if not self._tokens:
            self._invalid()
        schema, attribute, direct_sub_attribute = self._consume_attribute_path()
        value_filter: ScimFilterExpression | None = None
        selected_sub_attribute = direct_sub_attribute
        if self._kind_at("left_bracket"):
            if direct_sub_attribute is not None:
                self._invalid()
            self._index += 1
            value_filter = self._parse_or(allow_value_path=False)
            if not self._kind_at("right_bracket"):
                self._invalid()
            self._index += 1
            if self._kind_at("word"):
                suffix = str(self._tokens[self._index][1])
                if not suffix.startswith(".") or not _ATTRIBUTE.fullmatch(suffix[1:]):
                    self._invalid()
                selected_sub_attribute = suffix[1:]
                self._index += 1
        if self._index != len(self._tokens):
            self._invalid()
        return ScimPatchPath(
            attribute=attribute,
            schema=schema,
            value_filter=value_filter,
            sub_attribute=selected_sub_attribute,
        )

    def _parse_or(self, *, allow_value_path: bool) -> ScimFilterExpression:
        expression = self._parse_and(allow_value_path=allow_value_path)
        while self._word_at("or"):
            self._index += 1
            expression = ScimFilterExpression(
                operator="or",
                operands=(expression, self._parse_and(allow_value_path=allow_value_path)),
            )
        return expression

    def _parse_and(self, *, allow_value_path: bool) -> ScimFilterExpression:
        expression = self._parse_not(allow_value_path=allow_value_path)
        while self._word_at("and"):
            self._index += 1
            expression = ScimFilterExpression(
                operator="and",
                operands=(expression, self._parse_not(allow_value_path=allow_value_path)),
            )
        return expression

    def _parse_not(self, *, allow_value_path: bool) -> ScimFilterExpression:
        if self._word_at("not"):
            self._index += 1
            return ScimFilterExpression(
                operator="not",
                operands=(self._parse_not(allow_value_path=allow_value_path),),
            )
        return self._parse_primary(allow_value_path=allow_value_path)

    def _parse_primary(self, *, allow_value_path: bool) -> ScimFilterExpression:
        if self._kind_at("left_parenthesis"):
            self._index += 1
            self._depth += 1
            if self._depth > 4:
                self._invalid("SCIM expression nesting is too deep")
            expression = self._parse_or(allow_value_path=allow_value_path)
            if not self._kind_at("right_parenthesis"):
                self._invalid()
            self._index += 1
            self._depth -= 1
            return expression

        schema, attribute, sub_attribute = self._consume_attribute_path()
        if self._kind_at("left_bracket"):
            if not allow_value_path or sub_attribute is not None:
                self._invalid()
            self._index += 1
            value_filter = self._parse_or(allow_value_path=False)
            if not self._kind_at("right_bracket"):
                self._invalid()
            self._index += 1
            return ScimFilterExpression(
                operator="valuePath",
                attribute=attribute,
                operands=(value_filter,),
                schema=schema,
            )

        operator = self._consume_word().casefold()
        if operator == "pr":
            return ScimFilterExpression(
                operator=operator,
                attribute=attribute,
                schema=schema,
                sub_attribute=sub_attribute,
            )
        if operator not in {"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}:
            self._invalid("SCIM comparison operator is unsupported")
        if self._index >= len(self._tokens):
            self._invalid()
        kind, value = self._tokens[self._index]
        if kind not in {"string", "boolean", "number", "null"}:
            self._invalid()
        self._index += 1
        return ScimFilterExpression(
            operator=operator,
            attribute=attribute,
            value=cast(str | bool | int | float | None, value),
            schema=schema,
            sub_attribute=sub_attribute,
        )

    def _consume_attribute_path(self) -> tuple[str | None, str, str | None]:
        raw = self._consume_word()
        schema: str | None = None
        path = raw
        for supported in _SUPPORTED_SCHEMAS:
            prefix = f"{supported}:"
            if raw.casefold().startswith(prefix.casefold()):
                schema = supported
                path = raw[len(prefix) :]
                break
        if ":" in path:
            self._invalid("SCIM schema URI is unsupported")
        parts = path.split(".")
        if len(parts) > 2 or any(_ATTRIBUTE.fullmatch(part) is None for part in parts):
            self._invalid("SCIM attribute path is invalid")
        return schema, parts[0], parts[1] if len(parts) == 2 else None

    def _consume_word(self) -> str:
        if not self._kind_at("word"):
            self._invalid()
        value = str(self._tokens[self._index][1])
        self._index += 1
        return value

    def _kind_at(self, kind: str) -> bool:
        return self._index < len(self._tokens) and self._tokens[self._index][0] == kind

    def _word_at(self, value: str) -> bool:
        return self._kind_at("word") and str(self._tokens[self._index][1]).casefold() == value

    def _tokenize(self, value: str) -> list[tuple[str, object]]:
        tokens: list[tuple[str, object]] = []
        delimiters = {
            "(": "left_parenthesis",
            ")": "right_parenthesis",
            "[": "left_bracket",
            "]": "right_bracket",
        }
        index = 0
        while index < len(value):
            if value[index].isspace():
                index += 1
                continue
            delimiter = delimiters.get(value[index])
            if delimiter is not None:
                tokens.append((delimiter, value[index]))
                index += 1
                continue
            if value[index] == '"':
                start = index
                index += 1
                escaped = False
                while index < len(value):
                    character = value[index]
                    index += 1
                    if escaped:
                        escaped = False
                    elif character == "\\":
                        escaped = True
                    elif character == '"':
                        break
                else:
                    self._invalid()
                try:
                    decoded = json.loads(value[start:index])
                except json.JSONDecodeError as error:
                    raise ScimSyntaxError(
                        self._error_type, "SCIM expression is invalid"
                    ) from error
                if not isinstance(decoded, str) or len(decoded) > 320:
                    self._invalid()
                tokens.append(("string", decoded))
                continue
            start = index
            while (
                index < len(value)
                and not value[index].isspace()
                and value[index] not in delimiters
            ):
                index += 1
            word = value[start:index]
            if not word or len(word) > 512:
                self._invalid()
            normalized = word.casefold()
            if normalized in {"true", "false"}:
                tokens.append(("boolean", normalized == "true"))
            elif normalized == "null":
                tokens.append(("null", None))
            elif _NUMBER.fullmatch(word):
                number = json.loads(word)
                tokens.append(("number", number))
            else:
                tokens.append(("word", word))
        return tokens

    def _invalid(self, message: str = "SCIM expression is invalid") -> NoReturn:
        raise ScimSyntaxError(self._error_type, message)


def parse_scim_filter(value: str) -> ScimFilterExpression:
    return _ScimExpressionParser(value, error_type="invalidFilter").parse_filter()


def parse_scim_patch_path(value: str) -> ScimPatchPath:
    return _ScimExpressionParser(value, error_type="invalidPath").parse_patch_path()


def expected_core_schema(resource_type: str) -> str:
    try:
        return _CORE_SCHEMAS[resource_type.casefold()]
    except KeyError as error:  # pragma: no cover - internal callers use User or Group
        raise ValueError(f"unsupported SCIM resource type {resource_type}") from error


__all__ = [
    "ScimFilterExpression",
    "ScimPatchPath",
    "ScimSyntaxError",
    "expected_core_schema",
    "parse_scim_filter",
    "parse_scim_patch_path",
]
