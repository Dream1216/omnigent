from __future__ import annotations

import asyncio
import json
from uuid import UUID

import httpx
import pytest

from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
    LiteLLMManagementError,
)

_MANAGEMENT_KEY = "management-test-secret-never-rendered"
_PROVIDER_KEY = "provider-test-secret-never-rendered"
_ID = UUID("93b22d34-f4ec-46da-bc65-e404edbd151c")


def _configuration(**kwargs: object) -> LiteLLMManagementConfiguration:
    return LiteLLMManagementConfiguration(
        base_url="https://litellm.test", management_key=_MANAGEMENT_KEY, **kwargs
    )


def _client(handler) -> LiteLLMManagementClient:
    return LiteLLMManagementClient(_configuration(), transport=httpx.MockTransport(handler))


def test_configuration_does_not_render_management_key() -> None:
    assert _MANAGEMENT_KEY not in repr(_configuration())


@pytest.mark.parametrize(
    "url",
    (
        "http://litellm.test",
        "https://user:password@litellm.test",
        "https://litellm.test/v1",
        "https://litellm.test?key=unsafe",
        "https://litellm.test#fragment",
        "https://litellm.test:invalid-port",
        "https://litellm.\ntest",
        "file:///etc/passwd",
    ),
)
def test_rejects_non_admitted_management_address(url: str) -> None:
    with pytest.raises(ValueError, match="configuration is invalid"):
        LiteLLMManagementConfiguration(base_url=url, management_key=_MANAGEMENT_KEY)


def test_internal_http_requires_exact_deployment_owned_host() -> None:
    config = LiteLLMManagementConfiguration(
        base_url="http://litellm-isolated:4000",
        management_key=_MANAGEMENT_KEY,
        allowed_http_hosts=("litellm-isolated",),
    )
    assert config.base_url == "http://litellm-isolated:4000"


def test_model_view_never_returns_provider_secrets() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/model/info"
        assert request.headers["authorization"] == f"Bearer {_MANAGEMENT_KEY}"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "model_name": "deepseek-v4-pro-r1",
                        "model_info": {"id": str(_ID), "secret": _PROVIDER_KEY},
                        "litellm_params": {
                            "model": "deepseek/deepseek-v4-pro",
                            "api_key": _PROVIDER_KEY,
                            "litellm_credential_name": "managed-credential-r1",
                        },
                    }
                ]
            },
        )

    values = asyncio.run(_client(upstream).list_deployments())
    assert values[0].id == str(_ID)
    assert values[0].credential_name == "managed-credential-r1"
    assert _PROVIDER_KEY not in repr(values)


def test_projects_credential_through_fixed_management_endpoint() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/credentials"
        assert json.loads(request.content) == {
            "credential_name": "managed-credential-r1",
            "credential_info": {"custom_llm_provider": "deepseek"},
            "credential_values": {"api_key": _PROVIDER_KEY},
        }
        return httpx.Response(200, json={"success": True})

    asyncio.run(
        _client(upstream).create_deepseek_credential(
            name="managed-credential-r1", api_key=_PROVIDER_KEY
        )
    )


def test_deployment_uses_stable_id_and_disables_transport_retries() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert request.url.path == "/model/new"
        assert sent["model_info"]["id"] == str(_ID)
        assert sent["litellm_params"]["num_retries"] == 0
        assert sent["litellm_params"]["max_retries"] == 0
        assert sent["litellm_params"]["litellm_credential_name"] == "managed-r1"
        assert "api_key" not in sent["litellm_params"]
        return httpx.Response(200, json={"model_id": str(_ID)})

    asyncio.run(
        _client(upstream).create_deepseek_deployment(
            deployment_id=_ID,
            alias="deepseek-v4-pro-r1",
            model="deepseek-v4-pro",
            credential_name="managed-r1",
        )
    )


def test_rejects_unapproved_provider_endpoint_before_egress() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        pytest.fail("unapproved configuration must not reach LiteLLM")

    with pytest.raises(ValueError, match="not admitted"):
        asyncio.run(
            _client(upstream).create_deepseek_deployment(
                deployment_id=_ID,
                alias="deepseek-v4-pro-r1",
                model="deepseek-v4-pro",
                credential_name="managed-r1",
                provider_base_url="http://169.254.169.254",
            )
        )


@pytest.mark.parametrize("name", ("../credentials", "https://other", "x\nInjected", ""))
def test_rejects_non_data_identifiers_before_egress(name: str) -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        pytest.fail("invalid identifier must not reach LiteLLM")

    with pytest.raises(ValueError, match="identifier is invalid"):
        asyncio.run(_client(upstream).create_deepseek_credential(name=name, api_key=_PROVIDER_KEY))


@pytest.mark.parametrize("status", (401, 403, 409, 429, 500, 503, 307))
def test_errors_are_redacted_and_never_retried(status: int) -> None:
    calls = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            status,
            headers={"Location": "https://other.test/credentials"},
            json={"error": f"unsafe provider response {_PROVIDER_KEY} {_MANAGEMENT_KEY}"},
        )

    with pytest.raises(LiteLLMManagementError) as error:
        asyncio.run(
            _client(upstream).create_deepseek_credential(name="managed-r1", api_key=_PROVIDER_KEY)
        )
    assert len(calls) == 1
    assert error.value.uncertain is (status >= 500 or 300 <= status < 400)
    assert _PROVIDER_KEY not in str(error.value)
    assert _MANAGEMENT_KEY not in str(error.value)


def test_transport_timeout_marks_write_uncertain_without_replay() -> None:
    calls = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ReadTimeout(_PROVIDER_KEY, request=request)

    with pytest.raises(LiteLLMManagementError) as error:
        asyncio.run(
            _client(upstream).create_deepseek_credential(name="managed-r1", api_key=_PROVIDER_KEY)
        )
    assert len(calls) == 1
    assert error.value.uncertain
    assert _PROVIDER_KEY not in str(error.value)


@pytest.mark.parametrize(
    "content",
    (b"not-json", b"[]", b"x" * (1024 * 1024 + 1)),
    ids=("not-json", "wrong-shape", "oversized"),
)
def test_invalid_write_receipt_requires_reconciliation(content: bytes) -> None:
    with pytest.raises(LiteLLMManagementError) as error:
        asyncio.run(
            _client(lambda _: httpx.Response(200, content=content)).delete_deployment(
                deployment_id=_ID
            )
        )
    assert error.value.uncertain
    assert error.value.code == "litellm_contract_invalid"


def test_inference_key_is_scoped_and_not_rendered() -> None:
    key = "inference-test-secret-never-rendered"

    def upstream(request: httpx.Request) -> httpx.Response:
        sent = json.loads(request.content)
        assert request.url.path == "/key/generate"
        assert sent["models"] == ["deepseek-v4-pro-r1"]
        assert sent["allowed_routes"] == [
            "/chat/completions",
            "/v1/chat/completions",
            "/responses",
            "/v1/responses",
        ]
        assert sent["duration"] == "3600s"
        return httpx.Response(200, json={"key": key, "unsafe": _MANAGEMENT_KEY})

    value = asyncio.run(
        _client(upstream).create_inference_key(
            aliases=("deepseek-v4-pro-r1",),
            key_alias="p0-inference",
            duration_seconds=3600,
        )
    )
    assert value.value == key
    assert key not in repr(value)


@pytest.mark.parametrize("duration", (True, -1, 0, 59, 86401, 3600.5, "3600"))
def test_invalid_key_duration_never_reaches_management_api(duration: int) -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        pytest.fail("invalid key lifetime must not reach LiteLLM")

    with pytest.raises(ValueError, match="scope is invalid"):
        asyncio.run(
            _client(upstream).create_inference_key(
                aliases=("deepseek-r1",), key_alias="probe", duration_seconds=duration
            )
        )
