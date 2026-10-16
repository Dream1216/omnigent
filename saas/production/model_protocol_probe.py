"""One bounded inference attempt after durable verification and budget admission."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

import httpx

from saas.control_plane.litellm_client import LiteLLMInferenceKey, validate_litellm_endpoint
from saas.control_plane.model_deployments import (
    CompiledModelDeploymentDraft,
    CreateModelDeploymentDraft,
    compile_model_deployment_draft,
)
from saas.control_plane.model_usage import ModelTokenUsage, ModelUsageError, normalize_model_usage

PROBE_INPUT_TOKEN_CEILING = 1024
PROBE_OUTPUT_TOKEN_CEILING = 32
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_LINE_BYTES = 16 * 1024
_MAX_RESPONSE_ID_BYTES = 2048


class ModelProtocolProbeError(RuntimeError):
    """Stable failure; any sent inference may need cost reconciliation."""

    def __init__(self, code: str, *, usage: ModelTokenUsage | None = None) -> None:
        self.code, self.usage = code, usage
        self.inference_may_have_usage = True
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ModelProtocolProbeConfiguration:
    base_url: str
    allowed_http_hosts: tuple[str, ...] = ()
    timeout_seconds: float = 30.0
    total_timeout_seconds: float = 45.0

    def __post_init__(self) -> None:
        validate_litellm_endpoint(
            self.base_url,
            allowed_http_hosts=self.allowed_http_hosts,
            timeout_seconds=self.timeout_seconds,
        )
        if type(self.total_timeout_seconds) not in {int, float} or not (
            self.timeout_seconds <= self.total_timeout_seconds <= 120
        ):
            raise ValueError("platform_model_probe_configuration_invalid")


@dataclass(frozen=True, slots=True)
class ModelProbeAdmission:
    """Binding from the durable worker claim, not an independent authorization source."""

    verification_id: UUID
    budget_reservation_id: UUID
    deployment_id: UUID
    configuration_sha256: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ModelProtocolProbeResult:
    verification_id: UUID
    budget_reservation_id: UUID
    deployment_id: UUID
    configuration_sha256: str
    wire_api: str
    output_token_limit: int
    usage: ModelTokenUsage
    latency_millis: int
    request_id_sha256: str | None
    request_attempts: int = 1
    response_id_length: int = 0


class _ProbeStream:
    def __init__(self, draft: CompiledModelDeploymentDraft, *, output_limit: int) -> None:
        self.responses = draft.wire_api == "openai_responses"
        self.models = {draft.alias, draft.public_model_id, "deepseek/" + draft.public_model_id}
        self.output_limit = output_limit
        self.pending = bytearray()
        self.received = 0
        self.output = self.model_seen = self.done = self.completed = self.finished = False
        self.identifier: str | None = None
        self.usage: ModelTokenUsage | None = None

    def feed(self, chunk: bytes) -> None:
        self.received += len(chunk)
        if self.received > _MAX_RESPONSE_BYTES:
            raise ModelProtocolProbeError("litellm_probe_response_oversized")
        self.pending.extend(chunk)
        while b"\n" in self.pending:
            line, _, remainder = self.pending.partition(b"\n")
            self.pending = bytearray(remainder)
            self._line(bytes(line).rstrip(b"\r"))
        if len(self.pending) > _MAX_LINE_BYTES:
            raise ModelProtocolProbeError("litellm_probe_response_oversized")

    def finish(self) -> ModelTokenUsage:
        if self.pending:
            self._line(bytes(self.pending).rstrip(b"\r"))
            self.pending.clear()
        if not self.model_seen or not self.output or not self.completed or self.usage is None:
            raise ModelProtocolProbeError("litellm_probe_incomplete", usage=self.usage)
        if not self.responses and (not self.done or not self.finished):
            raise ModelProtocolProbeError("litellm_probe_incomplete", usage=self.usage)
        return self.usage

    def _identity(self, document: dict[str, object]) -> None:
        model = document.get("model")
        if model is not None:
            if not isinstance(model, str) or model not in self.models:
                raise ModelProtocolProbeError("litellm_probe_model_mismatch")
            self.model_seen = True
        identifier = document.get("id")
        if identifier is not None:
            if (
                not isinstance(identifier, str)
                or not 1 <= len(identifier) <= _MAX_RESPONSE_ID_BYTES
                or any(ord(char) < 33 or ord(char) > 126 for char in identifier)
            ):
                raise ModelProtocolProbeError("litellm_probe_identity_invalid")
            if self.identifier is not None and self.identifier != identifier:
                raise ModelProtocolProbeError("litellm_probe_identity_changed")
            self.identifier = identifier
        if document.get("error") is not None:
            raise ModelProtocolProbeError("litellm_probe_upstream_error")

    def _record_usage(self, value: object) -> None:
        try:
            usage = normalize_model_usage(value, responses=self.responses)
        except ModelUsageError:
            raise ModelProtocolProbeError("litellm_probe_usage_invalid") from None
        if (
            usage.input_tokens > PROBE_INPUT_TOKEN_CEILING
            or not 0 < usage.output_tokens <= self.output_limit
            or (self.usage is not None and self.usage != usage)
        ):
            raise ModelProtocolProbeError("litellm_probe_usage_invalid")
        self.usage = usage

    def _line(self, line: bytes) -> None:
        if len(line) > _MAX_LINE_BYTES:
            raise ModelProtocolProbeError("litellm_probe_response_oversized")
        if not line.startswith(b"data:"):
            return
        data = line[5:].strip()
        if data == b"[DONE]":
            if self.done:
                raise ModelProtocolProbeError("litellm_probe_stream_invalid")
            self.done = True
            if not self.responses:
                self.completed = True
            return
        if self.done or (self.responses and self.completed):
            raise ModelProtocolProbeError("litellm_probe_stream_invalid")
        try:
            document = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ModelProtocolProbeError("litellm_probe_stream_invalid") from None
        if not isinstance(document, dict):
            raise ModelProtocolProbeError("litellm_probe_stream_invalid")
        if self.responses:
            self._responses_event(document)
        else:
            self._identity(document)
            choices = document.get("choices", [])
            if not isinstance(choices, list) or len(choices) > 1:
                raise ModelProtocolProbeError("litellm_probe_stream_invalid")
            for choice in choices:
                if (
                    not isinstance(choice, dict)
                    or type(choice.get("index", 0)) is not int
                    or choice.get("index", 0) != 0
                ):
                    raise ModelProtocolProbeError("litellm_probe_stream_invalid")
                delta = choice.get("delta", {})
                if (
                    not isinstance(delta, dict)
                    or delta.get("tool_calls")
                    or delta.get("function_call")
                ):
                    raise ModelProtocolProbeError("litellm_probe_unexpected_tool")
                text = delta.get("content")
                if text is not None and not isinstance(text, str):
                    raise ModelProtocolProbeError("litellm_probe_stream_invalid")
                self.output = self.output or bool(text)
                reason = choice.get("finish_reason")
                if reason is not None:
                    if not isinstance(reason, str) or reason not in {"stop", "length"}:
                        raise ModelProtocolProbeError("litellm_probe_incomplete")
                    self.finished = True
            if document.get("usage") is not None:
                self._record_usage(document["usage"])

    def _responses_event(self, document: dict[str, object]) -> None:
        if document.get("error") is not None:
            raise ModelProtocolProbeError("litellm_probe_upstream_error")
        kind = document.get("type")
        if not isinstance(kind, str):
            raise ModelProtocolProbeError("litellm_probe_stream_invalid")
        if kind in {"error", "response.failed", "response.incomplete"}:
            raise ModelProtocolProbeError("litellm_probe_incomplete")
        response = document.get("response")
        if isinstance(response, dict):
            self._identity(response)
            output = response.get("output", [])
            if not isinstance(output, list) or any(
                not isinstance(item, dict) or item.get("type") not in {"message", "reasoning"}
                for item in output
            ):
                raise ModelProtocolProbeError("litellm_probe_unexpected_tool")
        if "function_call" in kind or "tool_call" in kind or "mcp" in kind:
            raise ModelProtocolProbeError("litellm_probe_unexpected_tool")
        if kind == "response.output_text.delta":
            text = document.get("delta")
            if not isinstance(text, str):
                raise ModelProtocolProbeError("litellm_probe_stream_invalid")
            self.output = self.output or bool(text)
        item = document.get("item")
        if isinstance(item, dict) and item.get("type") not in {"message", "reasoning", None}:
            raise ModelProtocolProbeError("litellm_probe_unexpected_tool")
        if kind == "response.completed":
            if not isinstance(response, dict) or response.get("status") != "completed":
                raise ModelProtocolProbeError("litellm_probe_incomplete")
            self._record_usage(response.get("usage"))
            self.completed = True


class ModelProtocolProbe:
    """No management key, supplier key, retries, task replay, or publication authority."""

    def __init__(
        self,
        configuration: ModelProtocolProbeConfiguration,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._configuration, self._transport = configuration, transport

    async def run_admitted_probe(
        self,
        *,
        admission: ModelProbeAdmission,
        draft: CompiledModelDeploymentDraft,
        inference_key: LiteLLMInferenceKey,
        now: datetime | None = None,
    ) -> ModelProtocolProbeResult:
        at = now or datetime.now(timezone.utc)
        configuration = self._configuration
        try:
            compiled = compile_model_deployment_draft(
                CreateModelDeploymentDraft(
                    draft.public_model_id,
                    draft.display_name,
                    draft.connection_id,
                    draft.credential_version_id,
                    draft.generation - 1,
                    draft.wire_api,
                    draft.max_output_tokens,
                ),
                deployment_id=draft.deployment_id,
            )
            valid = (
                compiled == draft
                and all(
                    isinstance(value, UUID) and value.int
                    for value in (
                        admission.verification_id,
                        admission.budget_reservation_id,
                    )
                )
                and admission.deployment_id == draft.deployment_id
                and admission.configuration_sha256 == draft.configuration_sha256
                and admission.expires_at.tzinfo is not None
                and at.tzinfo is not None
                and admission.expires_at
                >= at + timedelta(seconds=configuration.total_timeout_seconds)
                and isinstance(inference_key.value, str)
                and 16 <= len(inference_key.value) <= 4096
                and all(33 <= ord(char) <= 126 for char in inference_key.value)
            )
        except (ValueError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("platform_model_probe_admission_invalid") from None
        responses = draft.wire_api == "openai_responses"
        output_limit = min(PROBE_OUTPUT_TOKEN_CEILING, draft.max_output_tokens)
        document: dict[str, object] = {"model": draft.alias, "stream": True}
        if responses:
            document.update({"input": "Reply with OK.", "max_output_tokens": output_limit})
        else:
            document.update(
                {
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "max_tokens": output_limit,
                    "stream_options": {"include_usage": True},
                }
            )
        stream = _ProbeStream(draft, output_limit=output_limit)
        started = time.monotonic()
        try:
            async with (
                asyncio.timeout(configuration.total_timeout_seconds),
                httpx.AsyncClient(
                    base_url=configuration.base_url.rstrip("/"),
                    transport=self._transport or httpx.AsyncHTTPTransport(retries=0),
                    timeout=configuration.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                ) as client,
                client.stream(
                    "POST",
                    "/v1/responses" if responses else "/v1/chat/completions",
                    headers={"Authorization": "Bearer " + inference_key.value},
                    json=document,
                ) as response,
            ):
                if response.status_code != 200:
                    raise ModelProtocolProbeError(
                        "litellm_probe_denied"
                        if response.status_code in {401, 403}
                        else "litellm_probe_rate_limited"
                        if response.status_code == 429
                        else "litellm_probe_rejected"
                    )
                if (
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "text/event-stream"
                ):
                    raise ModelProtocolProbeError("litellm_probe_stream_invalid")
                async for chunk in response.aiter_bytes():
                    stream.feed(chunk)
                usage = stream.finish()
        except (httpx.HTTPError, TimeoutError):
            raise ModelProtocolProbeError("litellm_probe_transport_uncertain") from None
        except ModelProtocolProbeError:
            raise
        except Exception:  # noqa: BLE001 - untrusted transport details cannot reach receipts.
            raise ModelProtocolProbeError("litellm_probe_transport_uncertain") from None
        return ModelProtocolProbeResult(
            admission.verification_id,
            admission.budget_reservation_id,
            draft.deployment_id,
            draft.configuration_sha256,
            draft.wire_api,
            output_limit,
            usage,
            max(0, round((time.monotonic() - started) * 1000)),
            sha256(stream.identifier.encode()).hexdigest() if stream.identifier else None,
            response_id_length=len(stream.identifier) if stream.identifier else 0,
        )
