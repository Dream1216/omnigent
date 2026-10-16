from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import httpx
import pytest

from saas.control_plane.litellm_client import LiteLLMInferenceKey
from saas.control_plane.model_deployments import (
    CreateModelDeploymentDraft,
    compile_model_deployment_draft,
)
from saas.control_plane.model_usage import ModelUsageError, normalize_model_usage
from saas.production.model_protocol_probe import (
    ModelProbeAdmission,
    ModelProtocolProbe,
    ModelProtocolProbeConfiguration,
    ModelProtocolProbeError,
)

_KEY = "isolated-model-probe-inference-secret"
_PRIVATE = "untrusted-provider-text-must-not-be-retained"


def _fixture(*, responses=False, output_limit=32):
    draft = compile_model_deployment_draft(
        CreateModelDeploymentDraft(
            "deepseek-isolated-contract",
            "isolated probe",
            uuid4(),
            uuid4(),
            0,
            "openai_responses" if responses else "openai_chat_completions",
            output_limit,
        ),
        deployment_id=uuid4(),
    )
    admission = ModelProbeAdmission(
        uuid4(),
        uuid4(),
        draft.deployment_id,
        draft.configuration_sha256,
        datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    return draft, admission


def _usage(*, responses=False, cached=True):
    return {
        "input_tokens" if responses else "prompt_tokens": 10,
        "output_tokens" if responses else "completion_tokens": 3,
        "total_tokens": 13,
        **(
            {
                "input_tokens_details" if responses else "prompt_tokens_details": {
                    "cached_tokens": 4
                }
            }
            if cached
            else {}
        ),
    }


def _events(draft):
    if draft.wire_api == "openai_responses":
        response = {"id": "response-isolated", "model": draft.public_model_id, "output": []}
        return [
            {"type": "response.created", "response": {**response, "status": "in_progress"}},
            {"type": "response.output_text.delta", "delta": _PRIVATE},
            {
                "type": "response.completed",
                "response": {
                    **response,
                    "status": "completed",
                    "usage": _usage(responses=True),
                },
            },
            "[DONE]",
        ]
    return [
        {
            "id": "chat-isolated",
            "model": draft.public_model_id,
            "choices": [
                {"index": 0, "delta": {"content": _PRIVATE}},
            ],
        },
        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        {"choices": [], "usage": _usage()},
        "[DONE]",
    ]


def _body(events):
    return b"".join(
        ("data: " + (item if isinstance(item, str) else json.dumps(item)) + "\n\n").encode()
        for item in events
    )


class _Fragments(httpx.AsyncByteStream):
    def __init__(self, body, *, size=7, interrupt=False):
        self.body, self.size, self.interrupt, self.closed = body, size, interrupt, False

    async def __aiter__(self):
        for offset in range(0, len(self.body), self.size):
            yield self.body[offset : offset + self.size]
        if self.interrupt:
            raise httpx.ReadError(_PRIVATE)

    async def aclose(self):
        self.closed = True


def _probe(handler):
    return ModelProtocolProbe(
        ModelProtocolProbeConfiguration(base_url="https://litellm.test"),
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize("size", (1, 7, 4096))
def test_one_bounded_request_returns_bound_metadata_and_never_provider_text(responses, size):
    draft, admission = _fixture(responses=responses)
    chunks = _Fragments(_body(_events(draft)), size=size)
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "POST"
        assert request.url.path == ("/v1/responses" if responses else "/v1/chat/completions")
        assert request.headers["authorization"] == "Bearer " + _KEY
        payload = json.loads(request.content)
        assert payload["model"] == draft.alias and payload["stream"] is True
        assert payload["max_output_tokens" if responses else "max_tokens"] == 32
        assert not set(payload) & {"api_key", "tools", "fallbacks", "max_retries", "metadata"}
        if not responses:
            assert payload["stream_options"] == {"include_usage": True}
        return httpx.Response(200, stream=chunks, headers={"content-type": "text/event-stream"})

    result = asyncio.run(
        _probe(handler).run_admitted_probe(
            admission=admission,
            draft=draft,
            inference_key=LiteLLMInferenceKey(_KEY),
        )
    )
    assert len(calls) == result.request_attempts == 1 and chunks.closed
    assert result.deployment_id == draft.deployment_id
    assert result.configuration_sha256 == draft.configuration_sha256
    assert result.budget_reservation_id == admission.budget_reservation_id
    assert result.verification_id == admission.verification_id
    assert result.usage.total_tokens == 13 and result.usage.input_cache_hit_tokens == 4
    assert (
        result.request_id_sha256
        == sha256(("response-isolated" if responses else "chat-isolated").encode()).hexdigest()
    )
    assert _PRIVATE not in repr(asdict(result)) and _KEY not in repr(result)
    assert "verified" not in asdict(result) and "runtime_enabled" not in asdict(result)


def test_probe_never_increases_a_smaller_draft_output_limit():
    draft, admission = _fixture(output_limit=3)

    def handler(request):
        assert json.loads(request.content)["max_tokens"] == 3
        return httpx.Response(
            200, content=_body(_events(draft)), headers={"content-type": "text/event-stream"}
        )

    result = asyncio.run(
        _probe(handler).run_admitted_probe(
            admission=admission,
            draft=draft,
            inference_key=LiteLLMInferenceKey(_KEY),
        )
    )
    assert result.output_token_limit == 3


@pytest.mark.parametrize(
    "change",
    (
        {"verification_id": UUID(int=0)},
        {"budget_reservation_id": UUID(int=0)},
        {"deployment_id": uuid4()},
        {"configuration_sha256": "f" * 64},
        {"expires_at": datetime.now(timezone.utc)},
        {"expires_at": datetime.now(timezone.utc).replace(tzinfo=None)},
    ),
)
def test_admission_identity_and_validity_fail_before_egress(change):
    draft, admission = _fixture()
    with pytest.raises(ValueError, match="admission_invalid"):
        asyncio.run(
            _probe(lambda _: pytest.fail("must not leave preflight")).run_admitted_probe(
                admission=replace(admission, **change),
                draft=draft,
                inference_key=LiteLLMInferenceKey(_KEY),
            )
        )


def test_forged_compiled_draft_and_secret_header_injection_fail_before_egress():
    draft, admission = _fixture()
    for changed_draft, key in (
        (replace(draft, alias="another-deployment"), _KEY),
        (draft, _KEY + "\nInjected: unsafe"),
    ):
        with pytest.raises(ValueError, match="admission_invalid"):
            asyncio.run(
                _probe(lambda _: pytest.fail("must not send")).run_admitted_probe(
                    admission=admission,
                    draft=changed_draft,
                    inference_key=LiteLLMInferenceKey(key),
                )
            )


@pytest.mark.parametrize("status", (401, 403, 429, 500, 503, 307))
def test_denial_redirects_and_server_errors_are_redacted_and_never_retried(status):
    draft, admission = _fixture()
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status, json={"error": _KEY + _PRIVATE}, headers={"location": "https://other.test"}
        )

    with pytest.raises(ModelProtocolProbeError) as rejected:
        asyncio.run(
            _probe(handler).run_admitted_probe(
                admission=admission,
                draft=draft,
                inference_key=LiteLLMInferenceKey(_KEY),
            )
        )
    assert len(calls) == 1 and rejected.value.inference_may_have_usage
    assert _KEY not in str(rejected.value) and _PRIVATE not in repr(rejected.value)
    assert "expired" not in rejected.value.code and "login" not in str(rejected.value)


@pytest.mark.parametrize(
    "failure",
    (
        "missing_usage",
        "missing_end",
        "model",
        "tool",
        "usage",
        "malformed",
        "after_end",
        "conflicting_usage",
        "identity",
        "oversized",
    ),
)
def test_invalid_chat_streams_cannot_become_successful_probe_evidence(failure):
    draft, admission = _fixture()
    events = _events(draft)
    if failure == "missing_usage":
        del events[2]
    elif failure == "missing_end":
        events.pop()
    elif failure == "model":
        events[0]["model"] = "unapproved-model"
    elif failure == "tool":
        events[0]["choices"][0]["delta"]["tool_calls"] = [{"name": "unexpected"}]
    elif failure == "usage":
        events[2]["usage"]["total_tokens"] = 999
    elif failure == "malformed":
        events.insert(2, "not-json-" + _KEY)
    elif failure == "after_end":
        events.append({"usage": _usage()})
    elif failure == "conflicting_usage":
        events.insert(3, {"usage": {**_usage(), "completion_tokens": 4, "total_tokens": 14}})
    elif failure == "identity":
        events[1]["id"] = "different-id"
    else:
        events[0]["choices"][0]["delta"]["content"] = "x" * (64 * 1024)
    stream = _Fragments(_body(events), size=4096)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=stream, headers={"content-type": "text/event-stream"})

    with pytest.raises(ModelProtocolProbeError) as rejected:
        asyncio.run(
            _probe(handler).run_admitted_probe(
                admission=admission,
                draft=draft,
                inference_key=LiteLLMInferenceKey(_KEY),
            )
        )
    assert len(calls) == 1 and stream.closed
    assert _KEY not in str(rejected.value) and _PRIVATE not in repr(rejected.value)


@pytest.mark.parametrize(
    "failure",
    ("incomplete", "tool_event", "tool_output", "missing_model", "output_limit", "bad_type"),
)
def test_responses_completion_and_actual_output_limit_are_required(failure):
    draft, admission = _fixture(responses=True)
    events = _events(draft)
    if failure == "incomplete":
        events[2]["type"] = "response.incomplete"
    elif failure == "tool_event":
        events.insert(2, {"type": "response.function_call_arguments.delta", "delta": "{}"})
    elif failure == "tool_output":
        events[2]["response"]["output"] = [{"type": "function_call"}]
    elif failure == "missing_model":
        del events[0]["response"]["model"]
        del events[2]["response"]["model"]
    elif failure == "output_limit":
        events[2]["response"]["usage"].update(output_tokens=33, total_tokens=43)
    else:
        events[2]["type"] = {"unsafe": _KEY}
    with pytest.raises(ModelProtocolProbeError):
        asyncio.run(
            _probe(
                lambda _: httpx.Response(
                    200,
                    content=_body(events),
                    headers={"content-type": "text/event-stream"},
                )
            ).run_admitted_probe(
                admission=admission, draft=draft, inference_key=LiteLLMInferenceKey(_KEY)
            )
        )


def test_partial_stream_transport_failure_is_uncertain_and_closes_without_replay():
    draft, admission = _fixture()
    stream = _Fragments(_body(_events(draft)[:1]), interrupt=True)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=stream, headers={"content-type": "text/event-stream"})

    with pytest.raises(ModelProtocolProbeError, match="transport_uncertain"):
        asyncio.run(
            _probe(handler).run_admitted_probe(
                admission=admission,
                draft=draft,
                inference_key=LiteLLMInferenceKey(_KEY),
            )
        )
    assert len(calls) == 1 and stream.closed


@pytest.mark.parametrize("responses", (False, True))
def test_usage_normalizer_preserves_standard_and_native_cache_accounting(responses):
    normalized = normalize_model_usage(_usage(responses=responses), responses=responses)
    native = {
        **_usage(responses=responses, cached=False),
        "prompt_cache_hit_tokens": 4,
        "prompt_cache_miss_tokens": 6,
    }
    assert normalized == normalize_model_usage(native, responses=responses)
    assert (
        normalized.input_cache_hit_tokens + normalized.input_cache_miss_tokens
        == normalized.input_tokens
    )
    assert (
        normalize_model_usage(
            _usage(responses=responses, cached=False), responses=responses
        ).input_cache_miss_tokens
        == 10
    )


@pytest.mark.parametrize(
    "change",
    (
        {"prompt_tokens": True},
        {"total_tokens": -1},
        {"completion_tokens": "3"},
        {"total_tokens": 14},
        {"prompt_tokens_details": {"cached_tokens": 11}},
        {"prompt_cache_hit_tokens": True},
        {"prompt_cache_miss_tokens": 5},
        {"prompt_tokens": 1 << 63},
    ),
)
def test_bad_usage_cannot_be_silently_coerced_or_replace_true_costs(change):
    with pytest.raises(ModelUsageError, match="usage_invalid"):
        normalize_model_usage({**_usage(), **change}, responses=False)
