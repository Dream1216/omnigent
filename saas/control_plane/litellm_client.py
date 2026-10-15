"""Narrow, single-attempt transport for platform-owned LiteLLM operations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

import httpx

_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_MAX_RESPONSE_BYTES = 1024 * 1024
_INFERENCE_ROUTES = (
    "/chat/completions",
    "/v1/chat/completions",
    "/responses",
    "/v1/responses",
)


class LiteLLMManagementError(RuntimeError):
    """Redacted failure; uncertain writes require reconciliation, not retry."""

    def __init__(self, code: str, *, uncertain: bool, status_code: int | None = None):
        self.code = code
        self.uncertain = uncertain
        self.status_code = status_code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LiteLLMManagementConfiguration:
    base_url: str
    management_key: str = field(repr=False)
    allowed_http_hosts: tuple[str, ...] = ()
    allowed_provider_base_urls: tuple[str, ...] = ("https://api.deepseek.com",)
    timeout_seconds: float = 20.0

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.base_url)
            port = parsed.port
        except ValueError:
            raise ValueError("LiteLLM management configuration is invalid") from None
        if (
            parsed.scheme not in {"http", "https"}
            or (port is not None and not 1 <= port <= 65535)
            or any(character.isspace() for character in self.base_url)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (parsed.scheme == "http" and parsed.hostname not in self.allowed_http_hosts)
            or not 1 <= self.timeout_seconds <= 120
            or not 16 <= len(self.management_key) <= 4096
            or not all(33 <= ord(character) <= 126 for character in self.management_key)
        ):
            raise ValueError("LiteLLM management configuration is invalid")


@dataclass(frozen=True, slots=True)
class LiteLLMDeploymentView:
    id: str
    model_name: str
    provider_model: str
    credential_name: str | None


@dataclass(frozen=True, slots=True)
class LiteLLMInferenceKey:
    value: str = field(repr=False)


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ValueError("LiteLLM managed identifier is invalid")
    return value


class LiteLLMManagementClient:
    """Called only after platform authorization and durable operation admission."""

    def __init__(
        self,
        configuration: LiteLLMManagementConfiguration,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._configuration = configuration
        self._transport = transport

    async def list_deployments(self) -> tuple[LiteLLMDeploymentView, ...]:
        payload = await self._request("GET", "/model/info")
        rows = payload.get("data")
        if not isinstance(rows, list):
            raise LiteLLMManagementError("litellm_contract_invalid", uncertain=False)
        result: list[LiteLLMDeploymentView] = []
        for row in rows:
            if not isinstance(row, dict):
                raise LiteLLMManagementError("litellm_contract_invalid", uncertain=False)
            info, params = row.get("model_info"), row.get("litellm_params")
            if not isinstance(info, dict) or not isinstance(params, dict):
                raise LiteLLMManagementError("litellm_contract_invalid", uncertain=False)
            identifier, name, model = info.get("id"), row.get("model_name"), params.get("model")
            credential = params.get("litellm_credential_name")
            if not all(isinstance(item, str) and item for item in (identifier, name, model)) or (
                credential is not None and not isinstance(credential, str)
            ):
                raise LiteLLMManagementError("litellm_contract_invalid", uncertain=False)
            result.append(
                LiteLLMDeploymentView(
                    id=str(identifier),
                    model_name=str(name),
                    provider_model=str(model),
                    credential_name=credential,
                )
            )
        return tuple(result)

    async def create_deepseek_credential(self, *, name: str, api_key: str) -> None:
        if not 16 <= len(api_key) <= 4096 or not all(
            33 <= ord(character) <= 126 for character in api_key
        ):
            raise ValueError("Provider credential is invalid")
        await self._request(
            "POST",
            "/credentials",
            {
                "credential_name": _name(name),
                "credential_info": {"custom_llm_provider": "deepseek"},
                "credential_values": {"api_key": api_key},
            },
        )

    async def create_deepseek_deployment(
        self,
        *,
        deployment_id: UUID,
        alias: str,
        model: str,
        credential_name: str,
        provider_base_url: str = "https://api.deepseek.com",
    ) -> None:
        if (
            deployment_id.int == 0
            or not model.startswith("deepseek-")
            or provider_base_url not in self._configuration.allowed_provider_base_urls
        ):
            raise ValueError("LiteLLM deployment is not admitted")
        await self._request(
            "POST",
            "/model/new",
            {
                "model_name": _name(alias),
                "litellm_params": {
                    "model": f"deepseek/{_name(model)}",
                    "api_base": provider_base_url,
                    "litellm_credential_name": _name(credential_name),
                    "num_retries": 0,
                    "max_retries": 0,
                },
                "model_info": {"id": str(deployment_id)},
            },
        )

    async def delete_deployment(self, *, deployment_id: UUID) -> None:
        if deployment_id.int == 0:
            raise ValueError("LiteLLM deployment is not admitted")
        await self._request("POST", "/model/delete", {"id": str(deployment_id)})

    async def create_inference_key(
        self, *, aliases: tuple[str, ...], key_alias: str, duration_seconds: int
    ) -> LiteLLMInferenceKey:
        if (
            not 1 <= len(aliases) <= 16
            or isinstance(duration_seconds, bool)
            or not isinstance(duration_seconds, int)
            or not 60 <= duration_seconds <= 86400
        ):
            raise ValueError("LiteLLM inference key model scope is invalid")
        payload = await self._request(
            "POST",
            "/key/generate",
            {
                "models": [_name(alias) for alias in aliases],
                "key_alias": _name(key_alias),
                "duration": f"{duration_seconds}s",
                "allowed_routes": list(_INFERENCE_ROUTES),
            },
        )
        value = payload.get("key")
        if (
            not isinstance(value, str)
            or not 16 <= len(value) <= 4096
            or not all(33 <= ord(character) <= 126 for character in value)
        ):
            raise LiteLLMManagementError("litellm_contract_invalid", uncertain=True)
        return LiteLLMInferenceKey(value=value)

    async def _request(
        self, method: str, path: str, document: dict[str, object] | None = None
    ) -> dict[str, object]:
        write = method != "GET"
        configuration = self._configuration
        try:
            async with (
                httpx.AsyncClient(
                    base_url=configuration.base_url.rstrip("/"),
                    headers={"Authorization": f"Bearer {configuration.management_key}"},
                    timeout=configuration.timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    transport=self._transport,
                ) as client,
                client.stream(method, path, json=document) as response,
            ):
                if not 200 <= response.status_code < 300:
                    code = (
                        "litellm_management_denied"
                        if response.status_code in {401, 403}
                        else "litellm_management_conflict"
                        if response.status_code == 409
                        else "litellm_management_rejected"
                    )
                    raise LiteLLMManagementError(
                        code,
                        status_code=response.status_code,
                        uncertain=write and (response.status_code >= 500 or response.is_redirect),
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > _MAX_RESPONSE_BYTES:
                        raise LiteLLMManagementError("litellm_contract_invalid", uncertain=write)
                payload = json.loads(content)
                if not isinstance(payload, dict):
                    raise ValueError
                return payload
        except httpx.HTTPError:
            raise LiteLLMManagementError(
                "litellm_management_unreachable", uncertain=write
            ) from None
        except (ValueError, UnicodeError):
            raise LiteLLMManagementError("litellm_contract_invalid", uncertain=write) from None
