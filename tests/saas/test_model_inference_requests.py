from __future__ import annotations

import json

import httpx
import pytest

from saas.production.platform_model_gateway import _request_document
from tests.saas.test_platform_model_gateway import _client, _ConfigurationReader


def _document(*, responses: bool) -> dict[str, object]:
    return {
        "model": "deepseek-flash",
        "stream": True,
        "max_output_tokens" if responses else "max_tokens": 32,
        "input" if responses else "messages": "hello" if responses else [],
    }


_ROUTING_OVERRIDES = (
    "api_key",
    "api_base",
    "base_url",
    "api_version",
    "organization",
    "project",
    "custom_llm_provider",
    "litellm_params",
    "litellm_credential_name",
    "credentials",
    "extra_body",
    "extra_headers",
    "headers",
    "proxy_server_request",
    "client",
    "num_retries",
    "max_retries",
    "fallbacks",
    "context_window_fallbacks",
    "timeout",
    "request_timeout",
    "routing_strategy",
    "deployment_id",
    "model_group",
    "mock_response",
    "future_unreviewed_option",
)


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize("field", _ROUTING_OVERRIDES)
def test_unknown_transport_and_routing_fields_never_reach_configuration_or_budget(
    monkeypatch, responses, field
) -> None:
    monkeypatch.setattr(
        _ConfigurationReader, "load", lambda _: pytest.fail("invalid request read credentials")
    )
    client, budgets, token = _client(
        httpx.MockTransport(lambda _: pytest.fail("invalid request sent inference"))
    )
    response = client.post(
        "/v1/responses" if responses else "/v1/chat/completions",
        headers={"Authorization": "Bearer " + token},
        json={**_document(responses=responses), field: "unapproved"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "platform_model_request_invalid"
    assert not budgets.reserved and not budgets.settled and not budgets.uncertain


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize(
    "override",
    (
        {"store": True},
        {"store": 0},
        {"metadata": {"team_id": "other"}},
        {"user": "other-tenant"},
        {"service_tier": "priority"},
        {"tools": [{"type": "web_search_preview"}]},
        {"tools": [{"type": "code_interpreter", "container": {"type": "auto"}}]},
        {"tools": [{"type": "function", "function": {"name": "ok"}, "api_key": "bad"}]},
        {"tool_choice": {"type": "mcp", "server_url": "https://unapproved.invalid"}},
    ),
)
def test_unapproved_state_identity_and_server_tools_are_rejected(responses, override) -> None:
    with pytest.raises(ValueError, match="platform_model_request_invalid"):
        _request_document(
            json.dumps({**_document(responses=responses), **override}).encode(),
            responses=responses,
        )


@pytest.mark.parametrize(
    "override",
    (
        {"previous_response_id": "resp_other"},
        {"background": True},
        {"reasoning": {"effort": "low", "api_key": "bad"}},
        {"text": {"format": {"type": "text"}, "api_base": "bad"}},
        {"include": ["web_search_call.action.sources"]},
        {"input": [{"type": "item_reference", "id": "other"}]},
        {
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_image", "image_url": "https://unapproved.invalid"}
                    ],
                }
            ]
        },
        {
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "1",
                    "output": [{"type": "input_file", "file_url": "https://unapproved.invalid"}],
                }
            ]
        },
    ),
)
def test_responses_rejects_unbounded_state_and_unverified_content(override) -> None:
    with pytest.raises(ValueError, match="platform_model_request_invalid"):
        _request_document(
            json.dumps({**_document(responses=True), **override}).encode(), responses=True
        )


@pytest.mark.parametrize(
    "override",
    (
        {"stream_options": {"include_usage": True, "extra_headers": {}}},
        {"stream_options": {"include_usage": "true"}},
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": "https://unapproved.invalid"}}
                    ],
                }
            ]
        },
        {
            "messages": [
                {"role": "user", "content": [{"type": "file", "file": {"file_id": "other"}}]}
            ]
        },
        {"input": "wrong-wire"},
    ),
)
def test_chat_rejects_nested_controls_and_unverified_content(override) -> None:
    with pytest.raises(ValueError, match="platform_model_request_invalid"):
        _request_document(json.dumps({**_document(responses=False), **override}).encode())


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize(
    "suffix",
    (
        b',"model":"deepseek-flash"',
        b',"temperature":NaN',
        b',"temperature":Infinity',
        b',"temperature":1e400',
    ),
)
def test_noncanonical_or_nonfinite_json_is_rejected(responses, suffix) -> None:
    raw = json.dumps(_document(responses=responses)).encode()[:-1] + suffix + b"}"
    with pytest.raises(ValueError, match="platform_model_request_invalid"):
        _request_document(raw, responses=responses)


@pytest.mark.parametrize("responses", (False, True))
def test_text_function_history_and_json_schema_reach_one_fenced_stream(responses) -> None:
    seen = []

    def upstream(request):
        seen.append(json.loads(request.content))
        body = (
            b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}\n\n'
            if responses
            else b'data: {"usage":{"prompt_tokens":1,"completion_tokens":1,'
            b'"total_tokens":2}}\n\ndata: [DONE]\n\n'
        )
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    function = {
        "name": "lookup",
        "description": "An Agent-local function, not server egress.",
        "parameters": {"type": "object", "properties": {"api_key": {"type": "string"}}},
        "strict": False,
    }
    document = _document(responses=responses)
    document.update(
        tools=[{"type": "function", **function}]
        if responses
        else [{"type": "function", "function": function}],
        tool_choice="auto",
        parallel_tool_calls=False,
        temperature=0.5,
        metadata={},
        user=None,
        service_tier="auto",
    )
    schema = {"type": "object", "properties": {"api_base": {"type": "string"}}}
    if responses:
        document.update(
            input=[
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "api_key is ordinary text"}],
                },
                {
                    "type": "function_call",
                    "name": "lookup",
                    "call_id": "c1",
                    "arguments": '{"api_key":"fixture"}',
                },
                {"type": "function_call_output", "call_id": "c1", "output": "result"},
                {
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "summary"}],
                    "encrypted_content": "opaque",
                },
            ],
            instructions="A normal task mentioning api_base.",
            reasoning={"effort": "low", "summary": "auto"},
            text={"format": {"type": "json_schema", "name": "result", "schema": schema}},
            include=["reasoning.encrypted_content"],
            store=None,
            background=False,
            previous_response_id=None,
            truncation="disabled",
        )
    else:
        document.update(
            messages=[
                {"role": "user", "content": "api_base is ordinary text"},
                {
                    "role": "assistant",
                    "content": None,
                    "reasoning_content": "brief",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{}"},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "c1", "content": "result"},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "result", "schema": schema},
            },
            stream_options={"include_usage": False},
        )
    client, budgets, token = _client(httpx.MockTransport(upstream))
    response = client.post(
        "/v1/responses" if responses else "/v1/chat/completions",
        headers={"Authorization": "Bearer " + token},
        json=document,
    )
    assert response.status_code == 200
    assert len(seen) == len(budgets.reserved) == len(budgets.settled) == 1
    assert not budgets.uncertain and not budgets.released
    sent = seen[0]
    assert sent["tools"] == document["tools"]
    assert (
        sent["input" if responses else "messages"]
        == document["input" if responses else "messages"]
    )
    assert not {"metadata", "user", "previous_response_id", "service_tier"} & sent.keys()
    if responses:
        assert sent["store"] is False and sent["text"] == document["text"]
    else:
        assert sent["stream_options"] == {"include_usage": True}
        assert sent["response_format"] == document["response_format"]
