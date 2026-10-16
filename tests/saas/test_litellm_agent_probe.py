from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from omnigent.inner.executor import TextChunk, TurnComplete
from saas.scripts import litellm_agent_probe as probe


def test_agent_probe_bounds_each_protocol_and_closes_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocols = []
    closed = []
    original_transport = probe.ProbeHTTPTransport
    monkeypatch.setattr(
        probe,
        "ProbeHTTPTransport",
        lambda **kwargs: original_transport(
            **kwargs, delegate=httpx.MockTransport(lambda _: httpx.Response(200))
        ),
    )

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["max_retries"] == 0
            self.http = kwargs["http_client"]

        async def close(self):
            await self.http.aclose()

    monkeypatch.setattr(probe, "AsyncOpenAI", Client)

    class Executor:
        def __init__(self, **kwargs):
            self.protocol = kwargs["use_responses"]
            self.client = kwargs["client"]
            protocols.append(self.protocol)
            assert kwargs["retry_policy"].max_retries == 0
            assert kwargs["retry_policy"].timeout_per_request_s == 30

        async def run_turn(self, messages, tools, system_prompt, config):
            assert not tools
            assert config.extra == {"max_tokens": 32, "max_turns": 1}
            await self.client.http.post(
                "http://probe/v1/" + ("responses" if self.protocol else "chat/completions"),
                json={
                    "model": "probe",
                    "stream": True,
                    "max_output_tokens" if self.protocol else "max_tokens": 32,
                    "input" if self.protocol else "messages": "hello" if self.protocol else [],
                },
            )
            yield TextChunk(text="OK")
            yield TurnComplete(response="OK", usage={"total_tokens": 22})

        async def close(self):
            closed.append(self.protocol)

    monkeypatch.setattr(probe, "OpenAIAgentsSDKExecutor", Executor)
    result = asyncio.run(
        probe.probe_agent(base_url="http://probe/v1", api_key="synthetic", model="probe")
    )
    assert protocols == closed == [False, True]
    assert all(row["passed"] for row in result.values())


def test_chat_probe_reuses_platform_usage_enforcement() -> None:
    seen = []

    async def run() -> None:
        transport = probe.ProbeHTTPTransport(
            url="https://probe/v1/chat/completions",
            model="probe",
            delegate=httpx.MockTransport(
                lambda request: seen.append(json.loads(request.content)) or httpx.Response(200)
            ),
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await client.post(
                "https://probe/v1/chat/completions",
                json={"model": "probe", "stream": True, "max_tokens": 32, "messages": []},
            )

    asyncio.run(run())
    assert seen[0]["stream_options"] == {"include_usage": True}


def test_probe_transport_prevents_hidden_second_request() -> None:
    calls = []

    async def run() -> None:
        transport = probe.ProbeHTTPTransport(
            url="https://probe/v1/responses",
            model="probe",
            delegate=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )
        async with httpx.AsyncClient(transport=transport) as client:
            document = {
                "model": "probe",
                "stream": True,
                "max_output_tokens": 32,
                "input": "hello",
            }
            await client.post("https://probe/v1/responses", json=document)
            with pytest.raises(httpx.TransportError, match="contract_rejected"):
                await client.post("https://probe/v1/responses", json=document)
        assert transport.attempts == 1 and transport.blocked

    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize(
    "overrides",
    (
        {"max_output_tokens": 33},
        {"tools": [{"type": "function"}]},
        {"stream": False},
        {"model": "other"},
        {"api_key": "caller-override"},
        {"extra_body": {"model": "other"}},
        {"num_retries": 2},
        {"store": True},
    ),
)
def test_probe_transport_rejects_unbounded_or_unapproved_payload(overrides) -> None:
    async def run() -> None:
        transport = probe.ProbeHTTPTransport(
            url="https://probe/v1/responses",
            model="probe",
            delegate=httpx.MockTransport(lambda _: pytest.fail("must reject before egress")),
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.TransportError, match="contract_rejected"):
                await client.post(
                    "https://probe/v1/responses",
                    json={
                        "model": "probe",
                        "stream": True,
                        "max_output_tokens": 32,
                        "input": "hello",
                        **overrides,
                    },
                )
        assert transport.attempts == 0

    asyncio.run(run())
