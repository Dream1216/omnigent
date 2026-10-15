"""Bounded Omnigent executor probe; no user tasks or response bodies are retained."""

from __future__ import annotations

import asyncio
import json

import httpx
from openai import AsyncOpenAI

from omnigent.inner.executor import ExecutorConfig, ExecutorError, TextChunk, TurnComplete
from omnigent.inner.openai_agents_sdk_executor import OpenAIAgentsSDKExecutor
from omnigent.spec.types import RetryPolicy
from saas.production.platform_model_gateway import _streaming_document


class ProbeHTTPTransport(httpx.AsyncBaseTransport):
    """Only one bounded model request may leave each protocol probe."""

    def __init__(
        self,
        *,
        url: str,
        model: str,
        delegate: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = httpx.URL(url)
        self.model = model
        self.attempts = 0
        self.blocked = False
        self.status_code: int | None = None
        self.delegate = delegate or httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            document = json.loads(request.content)
        except (ValueError, UnicodeError):
            document = {}
        if not isinstance(document, dict):
            document = {}
        limit = (
            document.get("max_output_tokens")
            if self.url.path.endswith("/responses")
            else document.get("max_completion_tokens") or document.get("max_tokens")
        )
        if (
            self.attempts != 0
            or request.method != "POST"
            or request.url != self.url
            or document.get("model") != self.model
            or document.get("stream") is not True
            or isinstance(limit, bool)
            or limit != 32
            or document.get("tools")
        ):
            self.blocked = True
            raise httpx.TransportError("probe_request_contract_rejected")
        # The platform gateway, not a non-OpenAI SDK default, requests usage.
        # Reuse its exact shaping contract for this isolated protocol probe.
        document = _streaming_document(document, responses=self.url.path.endswith("/responses"))
        headers = request.headers.copy()
        headers.pop("content-length", None)
        request = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            content=json.dumps(document).encode(),
            extensions=request.extensions,
        )
        self.attempts += 1
        response = await self.delegate.handle_async_request(request)
        self.status_code = response.status_code
        return response

    async def aclose(self) -> None:
        await self.delegate.aclose()


async def probe_agent(
    *, base_url: str, api_key: str, model: str
) -> dict[str, dict[str, bool | int | None]]:
    results: dict[str, dict[str, bool | int | None]] = {}
    for use_responses in (False, True):
        guard = ProbeHTTPTransport(
            url=base_url.rstrip("/") + ("/responses" if use_responses else "/chat/completions"),
            model=model,
        )
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            organization="",
            project="",
            max_retries=0,
            timeout=30,
            http_client=httpx.AsyncClient(
                transport=guard, timeout=30, follow_redirects=False, trust_env=False
            ),
        )
        executor = OpenAIAgentsSDKExecutor(
            client=client,
            model=model,
            use_responses=use_responses,
            retry_policy=RetryPolicy(max_retries=0, timeout_per_request_s=30),
        )
        completed, output, failed, usage_observed = False, False, False, False
        try:
            async with asyncio.timeout(60):
                async for event in executor.run_turn(
                    [{"role": "user", "content": "Reply with OK."}],
                    [],
                    "Respond briefly. Do not use tools.",
                    ExecutorConfig(model=model, extra={"max_tokens": 32, "max_turns": 1}),
                ):
                    completed = completed or isinstance(event, TurnComplete)
                    output = output or (isinstance(event, TextChunk) and bool(event.text))
                    failed = failed or isinstance(event, ExecutorError)
                    if isinstance(event, TurnComplete) and event.usage:
                        total = event.usage.get("total_tokens")
                        usage_observed = (
                            isinstance(total, int) and not isinstance(total, bool) and total > 0
                        )
        finally:
            await executor.close()
            await client.close()
        results["responses" if use_responses else "chat_completions"] = {
            "completed": completed,
            "streamed_output": output,
            "failed": failed,
            "usage_observed": usage_observed,
            "request_attempts": guard.attempts,
            "http_status": guard.status_code,
            "platform_gateway_request_contract_applied": True,
            "unexpected_request_blocked": guard.blocked,
            "passed": completed
            and output
            and usage_observed
            and not failed
            and guard.attempts == 1
            and not guard.blocked,
        }
    return results
