"""Closed inference fields; transport, routing and retained state are server-owned."""

from __future__ import annotations

import json
import math

_COMMON_FIELDS = frozenset(
    {"model", "stream", "temperature", "top_p", "tools", "tool_choice", "parallel_tool_calls"}
)
_CHAT_FIELDS = _COMMON_FIELDS | {
    "messages",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "frequency_penalty",
    "presence_penalty",
    "stop",
    "logprobs",
    "top_logprobs",
    "logit_bias",
    "seed",
    "response_format",
    "stream_options",
    "reasoning_effort",
    "store",
    "metadata",
    "user",
    "service_tier",
}
_RESPONSES_FIELDS = _COMMON_FIELDS | {
    "input",
    "instructions",
    "max_output_tokens",
    "reasoning",
    "text",
    "include",
    "store",
    "background",
    "previous_response_id",
    "truncation",
    "metadata",
    "user",
    "service_tier",
    "prompt_cache_key",
}


def _invalid() -> ValueError:
    return ValueError("platform_model_request_invalid")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _invalid()
        document[key] = value
    return document


def _invalid_constant(_value: str) -> None:
    raise _invalid()


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise _invalid()
    return number


def _object(value: object, *, fields: set[str] | frozenset[str]) -> dict:
    if not isinstance(value, dict) or not set(value) <= fields:
        raise _invalid()
    return value


def _function_tools(document: dict, *, responses: bool) -> None:
    tools = document.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            raise _invalid()
        for tool in tools:
            row = _object(
                tool,
                fields={"type", "name", "description", "parameters", "strict"}
                if responses
                else {"type", "function"},
            )
            if row.get("type") != "function":
                raise _invalid()
            function = (
                row
                if responses
                else _object(
                    row.get("function"), fields={"name", "description", "parameters", "strict"}
                )
            )
            if not isinstance(function.get("name"), str) or not function["name"]:
                raise _invalid()
    choice = document.get("tool_choice")
    if choice is None or (isinstance(choice, str) and choice in {"auto", "none", "required"}):
        return
    row = _object(choice, fields={"type", "name"} if responses else {"type", "function"})
    if row.get("type") != "function":
        raise _invalid()
    function = row if responses else _object(row.get("function"), fields={"name"})
    if not isinstance(function.get("name"), str) or not function["name"]:
        raise _invalid()


def decode_inference_request(raw: bytes, *, responses: bool) -> dict[str, object]:
    """Reject unknown fields before budget admission, without inspecting user text/schema."""

    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
        document = _object(document, fields=_RESPONSES_FIELDS if responses else _CHAT_FIELDS)
        # Null SDK defaults are harmless; nonempty identity and metadata cannot override policy.
        for field in ("metadata", "user", "previous_response_id"):
            if field in document:
                value = document.pop(field)
                if value is not None and not (field == "metadata" and value == {}):
                    raise _invalid()
        for field in ("store", "background"):
            if field in document:
                value = document[field]
                if value is not None and value is not False:
                    raise _invalid()
                document[field] = False
        tier = document.pop("service_tier", None)
        if tier is not None and tier not in ("auto", "default"):
            raise _invalid()
        _function_tools(document, responses=responses)
        _text_inputs(document, responses=responses)
        if responses:
            document["store"] = False
            _responses_options(document)
        else:
            options = document.get("stream_options")
            if options is not None:
                options = _object(options, fields={"include_usage"})
                if "include_usage" in options and type(options["include_usage"]) is not bool:
                    raise _invalid()
        return document
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _invalid() from None


def _responses_options(document: dict) -> None:
    reason = document.get("reasoning")
    if reason is not None:
        _object(reason, fields={"effort", "summary"})
    text = document.get("text")
    if text is not None:
        text = _object(text, fields={"format", "verbosity"})
        if text.get("format") is not None:
            _object(text["format"], fields={"type", "name", "description", "schema", "strict"})
    include = document.get("include")
    if include is not None and (
        not isinstance(include, list)
        or any(item != "reasoning.encrypted_content" for item in include)
    ):
        raise _invalid()
    if document.get("truncation") not in (None, "disabled", "auto"):
        raise _invalid()


def _text_content(value: object) -> None:
    if value is None or isinstance(value, str):
        return
    if not isinstance(value, list):
        raise _invalid()
    for block in value:
        row = _object(block, fields={"type", "text", "annotations", "logprobs"})
        if row.get("type") not in {
            "text",
            "input_text",
            "output_text",
            "summary_text",
        } or not isinstance(row.get("text"), str):
            raise _invalid()


def _text_inputs(document: dict, *, responses: bool) -> None:
    value = document.get("input" if responses else "messages")
    if responses and isinstance(value, str):
        return
    if not isinstance(value, list):
        raise _invalid()
    for item in value:
        if not isinstance(item, dict):
            raise _invalid()
        kind = item.get("type", "message") if responses else "message"
        if kind == "message":
            row = _object(
                item,
                fields={"type", "id", "status", "role", "content"}
                if responses
                else {
                    "role",
                    "content",
                    "name",
                    "tool_call_id",
                    "tool_calls",
                    "function_call",
                    "reasoning_content",
                },
            )
            if row.get("role") not in {
                "system",
                "developer",
                "user",
                "assistant",
                "tool",
                "function",
            }:
                raise _invalid()
            _text_content(row.get("content"))
        elif kind == "function_call":
            row = _object(item, fields={"type", "id", "status", "name", "arguments", "call_id"})
            if not all(isinstance(row.get(key), str) for key in ("name", "arguments", "call_id")):
                raise _invalid()
        elif kind == "function_call_output":
            row = _object(item, fields={"type", "id", "status", "call_id", "output"})
            if not isinstance(row.get("call_id"), str):
                raise _invalid()
            _text_content(row.get("output"))
        elif kind == "reasoning":
            row = _object(item, fields={"type", "id", "status", "summary", "encrypted_content"})
            _text_content(row.get("summary"))
        else:
            raise _invalid()
